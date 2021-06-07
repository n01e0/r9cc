use crate::gen_ir::{Function, IROp};
use crate::util::roundup;
use crate::{emit, Scope, Var, REGS_N};

use std::fmt;
use std::sync::Mutex;

// Quoted from 9cc
// > This pass generates x86-64 assembly from IR.

lazy_static! {
    static ref LABEL: Mutex<usize> = Mutex::new(0);
}

struct ObfuscateInst {
    call: bool,
    jmp: bool,
    ret: bool,
    mov: bool,
    lea: bool,
    cmp: bool,
    neg: bool,
    and: bool,
    or: bool,
    xor: bool,
    shift: bool,
    mod_: bool,
}

impl ObfuscateInst {
    pub fn from(v: Vec<&str>) -> Self {
        ObfuscateInst {
            call: v.iter().any(|&i| i == "call" || i == "*"),
            jmp: v.iter().any(|&i| i == "jmp" || i == "*"),
            ret: v.iter().any(|&i| i == "ret" || i == "*"),
            mov: v.iter().any(|&i| i == "mov" || i == "*"),
            lea: v.iter().any(|&i| i == "lea" || i == "*"),
            cmp: v.iter().any(|&i| i == "cmp" || i == "*"),
            neg: v.iter().any(|&i| i == "neg" || i == "*"),
            and: v.iter().any(|&i| i == "and" || i == "*"),
            or: v.iter().any(|&i| i == "or" || i == "*"),
            xor: v.iter().any(|&i| i == "xor" || i == "*"),
            shift: v.iter().any(|&i| i == "shift" || i == "*"),
            mod_: v.iter().any(|&i| i == "mod" || i == "*"),
        }
    }

    pub fn any(&self) -> bool {
        self.call
            || self.jmp
            || self.ret
            || self.mov
            || self.lea
            || self.cmp
            || self.neg
            || self.and
            || self.or
            || self.xor
            || self.shift
            || self.mod_
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
enum REGS {
    r10,
    r11,
    rbx,
    r12,
    r13,
    r14,
    r15,
}

impl fmt::Display for REGS {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

fn regs(index: usize) -> &'static str {
    match index {
        0 => "r10",
        1 => "r11",
        2 => "rbx",
        3 => "r12",
        4 => "r13",
        5 => "r14",
        6 => "r15",
        _ => panic!("index out of bounds"),
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
enum REGS8 {
    r10b,
    r11b,
    bl,
    r12b,
    r13b,
    r14b,
    r15b,
}

impl fmt::Display for REGS8 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

fn regs8(index: usize) -> &'static str {
    match index {
        0 => "r10b",
        1 => "r11b",
        2 => "bl",
        3 => "r12b",
        4 => "r13b",
        5 => "r14b",
        6 => "r15b",
        _ => panic!("index out of bounds"),
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
enum REGS32 {
    r10d,
    r11d,
    ebx,
    r12d,
    r13d,
    r14d,
    r15d,
}

impl fmt::Display for REGS32 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

fn regs32(index: usize) -> &'static str {
    match index {
        0 => "r10d",
        1 => "r11d",
        2 => "ebx",
        3 => "r12d",
        4 => "r13d",
        5 => "r14d",
        6 => "r15d",
        _ => panic!("index out of bounds"),
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
enum ARGREGS {
    rdi,
    rsi,
    rdx,
    rcx,
    r8,
    r9,
}

impl fmt::Display for ARGREGS {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

fn argregs(index: usize) -> &'static str {
    match index {
        0 => "rdi",
        1 => "rsi",
        2 => "rdx",
        3 => "rcx",
        4 => "r8",
        5 => "r9",
        _ => panic!("index out of bounds"),
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
enum ARGREGS8 {
    dil,
    sil,
    dl,
    cl,
    r8b,
    r9b,
}

impl fmt::Display for ARGREGS8 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

fn argregs8(index: usize) -> &'static str {
    match index {
        0 => "dil",
        1 => "dsil",
        2 => "ddl",
        3 => "dcl",
        4 => "dr8b",
        5 => "dr9b",
        _ => panic!("index out of bounds"),
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
enum ARGREGS32 {
    edi,
    esi,
    edx,
    ecx,
    r8d,
    r9d,
}

impl fmt::Display for ARGREGS32 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

fn argregs32(index: usize) -> &'static str {
    match index {
        0 => "edi",
        1 => "esi",
        2 => "edx",
        3 => "ecx",
        4 => "r8d",
        5 => "r9d",
        _ => panic!("index out of bounds"),
    }
}

fn backslash_escape(s: String, len: usize) -> String {
    let mut sb = String::new();
    for i in 0..len {
        if let Some(c) = s.chars().collect::<Vec<char>>().get(i) {
            // Issue: https://github.com/rust-lang/rfcs/issues/751
            let escaped = match c {
                // '\b' => Some('b'),
                // '\f' => Some('f'),
                '\n' => Some('n'),
                '\r' => Some('r'),
                '\t' => Some('t'),
                '\\' => Some('\\'),
                '\'' => Some('\''),
                '\"' => Some('\"'),
                _ => None,
            };
            if let Some(esc) = escaped {
                sb.push('\\');
                sb.push(esc);
            } else if c.is_ascii_graphic() || c == &' ' {
                sb.push(c.clone());
            } else {
                sb.push_str(&format!("\\{:o}", *c as i8));
            }
            if i == len - 1 {
                sb.push_str("\\000");
            }
        } else {
            sb.push_str("\\000");
        }
    }
    sb
}

fn reg(r: usize, size: u8) -> &'static str {
    match size {
        1 => regs8(r),
        4 => regs32(r),
        8 => regs(r),
        _ => unreachable!(),
    }
}

fn argreg(r: usize, size: u8) -> &'static str {
    match size {
        1 => argregs8(r),
        4 => argregs32(r),
        8 => argregs(r),
        _ => unreachable!(),
    }
}

fn gen(f: Function, obfuscate_inst: &ObfuscateInst) {
    use self::IROp::*;
    let ret = format!(".Lend{}", *LABEL.lock().unwrap());
    let mut call_gadget_id: usize = 0;
    *LABEL.lock().unwrap() += 1;

    println!(".text");
    println!(".global {}", f.name);
    println!("{}:", f.name);
    emit!("push rbp");
    emit!("mov rbp, rsp");
    emit!("sub rsp, {}", roundup(f.stacksize, 16));
    emit!("push r12");
    emit!("push r13");
    emit!("push r14");
    emit!("push r15");

    for ir in f.ir {
        let lhs = ir.lhs.unwrap();
        let rhs = ir.rhs.unwrap_or(0);
        match ir.op {
            Imm => {
                if obfuscate_inst.mov {
                    emit!("sub rsp, 0x18");
                    emit!("push rax");
                    emit!("lea rax, .Lgadget_mov_{}", regs(lhs));
                    emit!("mov [rsp+8], rax");
                    emit!("mov rax, {}", rhs as i32);
                    emit!("mov [rsp+0x10], rax");
                    emit!("lea rax, .Lcall_gadget_{}_{}", f.name, call_gadget_id);
                    emit!("mov [rsp+0x18], rax");
                    emit!("pop rax");
                    emit!("ret");
                    println!(".Lcall_gadget_{}_{}:", f.name, call_gadget_id);
                    call_gadget_id += 1;
                } else {
                    emit!("mov {}, {}", regs(lhs), rhs as i32)
                }
            }
            Mov => {
                if obfuscate_inst.mov {
                    emit!("sub rsp, 0x18");
                    emit!("push rax");
                    emit!("lea rax, .Lgadget_mov_{}", regs(lhs));
                    emit!("mov [rsp+8], rax");
                    emit!("mov [rsp+0x10], {}", regs(rhs));
                    emit!("lea rax, .Lcall_gadget_{}_{}", f.name, call_gadget_id);
                    emit!("mov [rsp+0x18], rax");
                    emit!("pop rax");
                    emit!("ret");
                    println!(".Lcall_gadget_{}_{}:", f.name, call_gadget_id);
                    call_gadget_id += 1;
                } else {
                    emit!("mov {}, {}", regs(lhs), regs(rhs));
                }
            }
            Return => {
                emit!("mov rax, {}", regs(lhs));
                if obfuscate_inst.ret {
                    emit!("lea rsp, [rsp-8]");
                    emit!("push rax");
                    emit!("lea rax, {}", ret);
                    emit!("mov [rsp+8], rax");
                    emit!("pop rax");
                    emit!("ret");
                } else {
                    emit!("jmp {}", ret);
                }
            }
            Call(name, nargs, args) => {
                for i in 0..nargs {
                    emit!("mov {}, {}", argregs(i), regs(args[i]));
                }
                emit!("push r10");
                emit!("push r11");
                emit!("mov rax, 0");
                if obfuscate_inst.call {
                    emit!("lea rsp, [rsp-0x10]");
                    emit!("push rax");
                    emit!("lea rax, {}", name);
                    emit!("mov [rsp+8], rax");
                    emit!("lea rax, .Lcall_gadget_{}_{}", f.name, call_gadget_id);
                    emit!("mov [rsp+0x10], rax");
                    emit!("pop rax");
                    emit!("ret");
                    println!(".Lcall_gadget_{}_{}:", f.name, call_gadget_id);
                    call_gadget_id += 1;
                } else {
                    emit!("call {}", name);
                }
                emit!("pop r11");
                emit!("pop r10");

                emit!("mov {}, rax", regs(lhs));
            }
            Label => println!(".L{}:", lhs),
            LabelAddr(name) => {
                if obfuscate_inst.lea {
                    emit!("sub rsp, 0x18");
                    emit!("push rax");
                    emit!("lea rax, .Lgadget_lea_{}", regs(lhs));
                    emit!("mov [rsp+8], rax");
                    emit!("lea rax, {}", name);
                    emit!("mov [rsp+0x10], rax");
                    emit!("lea rax, .Lcall_gadget_{}_{}", f.name, call_gadget_id);
                    emit!("mov [rsp+0x18], rax");
                    emit!("pop rax");
                    emit!("ret");
                    println!(".Lcall_gadget_{}_{}:", f.name, call_gadget_id);
                    call_gadget_id += 1;
                } else {
                    emit!("lea {}, {}", regs(lhs), name);
                }
            }
            Neg => {
                if obfuscate_inst.neg {
                    rop_enter(
                        format!(".Lgadget_neg_{}", regs(lhs)),
                        &f.name,
                        call_gadget_id,
                    );
                    emit!("ret");
                    println!(".Lcall_gadget_{}_{}:", f.name, call_gadget_id);
                    call_gadget_id += 1;
                } else {
                    emit!("neg {}", regs(lhs));
                }
            }
            EQ => {
                if obfuscate_inst.cmp {
                    rop_enter(
                        format!(".Lgadget_sete_{}", regs8(lhs)),
                        &f.name,
                        call_gadget_id,
                    );
                    emit!("cmp {}, {}", regs(lhs), regs(rhs));
                    emit!("ret");
                    println!(".Lcall_gadget_{}_{}:", f.name, call_gadget_id);
                    emit!("movzb {}, {}", regs(lhs), regs8(lhs));
                    call_gadget_id += 1;
                } else {
                    emit!("cmp {}, {}", regs(lhs), regs(rhs));
                    emit!("sete {}", regs8(lhs));
                    emit!("movzb {}, {}", regs(lhs), regs8(lhs));
                }
            }
            NE => {
                if obfuscate_inst.cmp {
                    rop_enter(
                        format!(".Lgadget_setne_{}", regs8(lhs)),
                        &f.name,
                        call_gadget_id,
                    );

                    emit!("cmp {}, {}", regs(lhs), regs(rhs));
                    emit!("ret");
                    println!(".Lcall_gadget_{}_{}:", f.name, call_gadget_id);
                    emit!("movzb {}, {}", regs(lhs), regs8(lhs));
                    call_gadget_id += 1;
                } else {
                    emit!("cmp {}, {}", regs(lhs), regs(rhs));
                    emit!("setne {}", regs8(lhs));
                    emit!("movzb {}, {}", regs(lhs), regs8(lhs));
                }
            }
            LT => {
                if obfuscate_inst.cmp {
                    rop_enter(
                        format!(".Lgadget_setl_{}", regs8(lhs)),
                        &f.name,
                        call_gadget_id,
                    );

                    emit!("cmp {}, {}", regs(lhs), regs(rhs));
                    emit!("ret");
                    println!(".Lcall_gadget_{}_{}:", f.name, call_gadget_id);
                    emit!("movzb {}, {}", regs(lhs), regs8(lhs));
                    call_gadget_id += 1;
                } else {
                    emit!("cmp {}, {}", regs(lhs), regs(rhs));
                    emit!("setl {}", regs8(lhs));
                    emit!("movzb {}, {}", regs(lhs), regs8(lhs));
                }
            }
            LE => {
                if obfuscate_inst.cmp {
                    rop_enter(
                        format!(".Lgadget_setle_{}", regs8(lhs)),
                        &f.name,
                        call_gadget_id,
                    );
                    emit!("cmp {}, {}", regs(lhs), regs(rhs));
                    emit!("ret");
                    println!(".Lcall_gadget_{}_{}:", f.name, call_gadget_id);
                    emit!("movzb {}, {}", regs(lhs), regs8(lhs));
                    call_gadget_id += 1;
                } else {
                    emit!("cmp {}, {}", regs(lhs), regs(rhs));
                    emit!("setle {}", regs8(lhs));
                    emit!("movzb {}, {}", regs(lhs), regs8(lhs));
                }
            }
            AND => {
                if obfuscate_inst.and {
                    rop_enter(
                        format!(".Lgaget_and_{}_{}", regs(lhs), regs(rhs)),
                        &f.name,
                        call_gadget_id,
                    );
                    emit!("ret");
                    println!(".Lcall_gadget_{}_{}:", f.name, call_gadget_id);
                    call_gadget_id += 1;
                } else {
                    emit!("and {}, {}", regs(lhs), regs(rhs));
                }
            }
            OR => {
                if obfuscate_inst.or {
                    rop_enter(
                        format!(".Lgadget_or_{}_{}", regs(lhs), regs(rhs)),
                        &f.name,
                        call_gadget_id,
                    );
                    emit!("ret");
                    println!(".Lcall_gadget_{}_{}:", f.name, call_gadget_id);
                    call_gadget_id += 1;
                } else {
                    emit!("or {}, {}", regs(lhs), regs(rhs));
                }
            }
            XOR => {
                if obfuscate_inst.xor {
                    rop_enter(
                        format!(".Lgadget_xor_{}_{}", regs(lhs), regs(rhs)),
                        &f.name,
                        call_gadget_id,
                    );
                    emit!("ret");
                    println!(".Lcall_gadget_{}_{}:", f.name, call_gadget_id);
                    call_gadget_id += 1;
                } else {
                    emit!("xor {}, {}", regs(lhs), regs(rhs));
                }
            }
            SHL => {
                emit!("mov cl, {}", regs8(rhs));
                if obfuscate_inst.shift {
                    rop_enter(
                        format!(".Lgadget_shl_{}", regs(lhs)),
                        &f.name,
                        call_gadget_id,
                    );
                    emit!("ret");
                    println!(".Lcall_gadget_{}_{}:", f.name, call_gadget_id);
                    call_gadget_id += 1;
                } else {
                    emit!("shl {}, cl", regs(lhs));
                }
            }
            SHR => {
                emit!("mov cl, {}", regs8(rhs));
                if obfuscate_inst.shift {
                    rop_enter(
                        format!(".Lgadget_shr_{}", regs(lhs)),
                        &f.name,
                        call_gadget_id,
                    );
                    emit!("ret");
                    println!(".Lcall_gadget_{}_{}:", f.name, call_gadget_id);
                    call_gadget_id += 1;
                } else {
                    emit!("shr {}, cl", regs(lhs));
                }
            }
            Mod => {
                /* Same meaning(?).
                 * emit!("mov rdx, 0");
                 * emit!("mov rax, {}", regs(lhs]);
                 */
                emit!("mov rax, {}", regs(lhs));
                if obfuscate_inst.mod_ {
                    rop_enter(
                        format!(".Lgadget_mod_{}_{}", regs(lhs), regs(rhs)),
                        &f.name,
                        call_gadget_id,
                    );
                    emit!("ret");
                    println!(".Lcall_gadget_{}_{}:", f.name, call_gadget_id);
                    call_gadget_id += 1;
                } else {
                    emit!("cqo"); // rax -> rdx:rax
                    emit!("div {}", regs(rhs));
                    emit!("mov {}, rdx", regs(lhs));
                }
            }
            Jmp => {
                if obfuscate_inst.jmp {
                    emit!("lea rsp, [rsp-8]");
                    emit!("push rax");
                    emit!("lea rax, .L{}", lhs);
                    emit!("mov [rsp+8], rax");
                    emit!("pop rax");
                    emit!("ret");
                } else {
                    emit!("jmp .L{}", lhs);
                }
            }
            If => {
                emit!("cmp {}, 0", regs(lhs));
                emit!("jne .L{}", rhs);
            }
            Unless => {
                emit!("cmp {}, 0", regs(lhs));
                emit!("je .L{}", rhs);
            }
            Load(size) => {
                if obfuscate_inst.mov {
                    rop_enter(
                        format!(".Lgadget_load_{}_{}", reg(lhs, size), regs(rhs)),
                        &f.name,
                        call_gadget_id,
                    );
                    emit!("ret");
                    println!(".Lcall_gadget_{}_{}:", f.name, call_gadget_id);
                    call_gadget_id += 1;
                } else {
                    emit!("mov {}, [{}]", reg(lhs, size), regs(rhs));
                    if size == 1 {
                        emit!("movzb {}, {}", regs(lhs), regs8(lhs));
                    }
                }
            }
            Store(size) => {
                if obfuscate_inst.mov {
                    rop_enter(
                        format!(".Lgadget_store_{}_{}", regs(lhs), reg(rhs, size)),
                        &f.name,
                        call_gadget_id,
                    );
                    emit!("ret");
                    println!(".Lcall_gadget_{}_{}:", f.name, call_gadget_id);
                    call_gadget_id += 1;
                } else {
                    emit!("mov [{}], {}", regs(lhs), reg(rhs, size))
                }
            }
            StoreArg(size) => emit!("mov [rbp-{}], {}", lhs, argreg(rhs, size)),
            Add => emit!("add {}, {}", regs(lhs), regs(rhs)),
            AddImm => emit!("add {}, {}", regs(lhs), rhs as i32),
            Sub => emit!("sub {}, {}", regs(lhs), regs(rhs)),
            SubImm => emit!("sub {}, {}", regs(lhs), rhs as i32),
            Bprel => emit!("lea {}, [rbp-{}]", regs(lhs), rhs),
            Mul => {
                emit!("mov rax, {}", regs(rhs));
                emit!("mul {}", regs(lhs));
                emit!("mov {}, rax", regs(lhs));
            }
            MulImm => {
                if rhs < 256 && rhs.count_ones() == 1 {
                    emit!("shl {}, {}", regs(lhs), rhs.trailing_zeros());
                } else {
                    emit!("mov rax, {}", rhs as i32);
                    emit!("mul {}", regs(lhs));
                    emit!("mov {}, rax", regs(lhs));
                }
            }
            Div => {
                emit!("mov rax, {}", regs(lhs));
                emit!("cqo");
                emit!("div {}", regs(rhs));
                emit!("mov {}, rax", regs(lhs));
            }
            Nop | Kill => (),
        }
    }

    println!("{}:", ret);
    emit!("pop r15");
    emit!("pop r14");
    emit!("pop r13");
    emit!("pop r12");
    emit!("mov rsp, rbp");
    emit!("pop rbp");
    emit!("ret");
}

pub fn gen_x86(globals: Vec<Var>, fns: Vec<Function>, obfuscate_inst: Vec<&str>) {
    let oi = ObfuscateInst::from(obfuscate_inst);
    println!(".intel_syntax noprefix");
    println!(".data");
    for var in globals {
        if let Scope::Global(data, len, is_extern) = var.scope {
            if is_extern {
                continue;
            }
            println!("{}:", var.name);
            emit!(".ascii \"{}\"", backslash_escape(data, len));
            continue;
        }
        unreachable!();
    }

    if oi.any() {
        println!(".text");
    }

    if oi.mov {
        for i in 0..REGS_N {
            println!(".Lgadget_mov_{}:", regs(i));
            emit!("pop {}", regs(i));
            emit!("ret");
        }

        for i in 0..REGS_N {
            for j in 0..REGS_N {
                println!(".Lgadget_store_{}_{}:", regs(i), regs(j));
                emit!("mov [{}], {}", regs(i), regs(j));
                emit!("ret");
                println!(".Lgadget_store_{}_{}:", regs(i), regs32(j));
                emit!("mov [{}], {}", regs(i), regs32(j));
                emit!("ret");
                println!(".Lgadget_store_{}_{}:", regs(i), regs8(j));
                emit!("mov [{}], {}", regs(i), regs8(j));
                emit!("ret");
            }
        }

        for i in 0..REGS_N {
            for j in 0..REGS_N {
                println!(".Lgadget_load_{}_{}:", regs(i), regs(j));
                emit!("mov {}, [{}]", regs(i), regs(j));
                emit!("ret");
                println!(".Lgadget_load_{}_{}:", regs32(i), regs(j));
                emit!("mov {}, [{}]", regs32(i), regs(j));
                emit!("ret");
                println!(".Lgadget_load_{}_{}:", regs8(i), regs(j));
                emit!("mov {}, [{}]", regs8(i), regs(j));
                emit!("movzb {}, {}", regs(i), regs8(i));
                emit!("ret");
            }
        }
    }

    if oi.lea {
        for i in 0..REGS_N {
            println!(".Lgadget_lea_{}:", regs(i));
            emit!("pop {}", regs(i));
            emit!("ret");
        }
    }

    if oi.neg {
        for i in 0..REGS_N {
            println!(".Lgadget_neg_{}:", regs(i));
            emit!("neg {}", regs(i));
            emit!("ret");
        }
    }

    if oi.cmp {
        for i in 0..REGS_N {
            println!(".Lgadget_sete_{}:", regs8(i));
            emit!("sete {}", regs8(i));
            emit!("ret");
            println!(".Lgadget_setne_{}:", regs8(i));
            emit!("setne {}", regs8(i));
            emit!("ret");
            println!(".Lgadget_setl_{}:", regs8(i));
            emit!("setl {}", regs8(i));
            emit!("ret");
            println!(".Lgadget_setle_{}:", regs8(i));
            emit!("setle {}", regs8(i));
            emit!("ret");
        }
    }

    if oi.and {
        for i in 0..REGS_N {
            for j in 0..REGS_N {
                println!(".Lgadget_and_{}_{}:", regs(i), regs(j));
                emit!("and {}, {}", regs(i), regs(j));
                emit!("ret");
            }
        }
    }

    if oi.or {
        for i in 0..REGS_N {
            for j in 0..REGS_N {
                println!(".Lgadget_or_{}_{}:", regs(i), regs(j));
                emit!("or {}, {}", regs(i), regs(j));
                emit!("ret");
            }
        }
    }

    if oi.xor {
        for i in 0..REGS_N {
            for j in 0..REGS_N {
                println!(".Lgadget_xor_{}_{}:", regs(i), regs(j));
                emit!("xor {}, {}", regs(i), regs(j));
                emit!("ret");
            }
        }
    }

    if oi.shift {
        for i in 0..REGS_N {
            println!(".Lgadget_shl_{}:", regs(i));
            emit!("shl {}, cl", regs(i));
            emit!("ret");
            println!(".Lgadget_shr_{}:", regs(i));
            emit!("shr {}, cl", regs(i));
            emit!("ret");
        }
    }

    if oi.mod_ {
        for i in 0..REGS_N {
            for j in 0..REGS_N {
                println!(".Lgadget_mod_{}_{}:", regs(i), regs(j));
                emit!("cqo"); // rax -> rdx:rax
                emit!("div {}", regs(j));
                emit!("mov {}, rdx", regs(i));
                emit!("ret");
            }
        }
    }

    for f in fns {
        gen(f, &oi);
    }
}

fn rop_enter(gadget_label: String, fname: &str, id: usize) {
    emit!("sub rsp, 0x10");
    emit!("push rax");
    emit!("lea rax, {}", gadget_label);
    emit!("mov [rsp+8], rax");
    emit!("lea rax, .Lcall_gadget_{}_{}", fname, id);
    emit!("mov [rsp+0x10], rax");
    emit!("pop rax");
}
