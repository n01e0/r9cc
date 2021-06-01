use crate::gen_ir::{Function, IROp};
use crate::util::roundup;
use crate::{Scope, Var, REGS_N};
use crate::{
    emit,
    mov,
    movzb,
    lea,
    sub,
    add,
    mul,
    div,
    neg,
    cqo,
    cmp,
    shl,
    shr,
    push,
    pop,
    ret,
    sete,
    setne,
    setl,
    setle
};

use std::sync::Mutex;
use std::fmt;

const REGS8: [&str; REGS_N] = ["r10b", "r11b", "bl", "r12b", "r13b", "r14b", "r15b"];
const REGS32: [&str; REGS_N] = ["r10d", "r11d", "ebx", "r12d", "r13d", "r14d", "r15d"];

// Quoted from 9cc
// > This pass generates x86-64 assembly from IR.

const ARGREGS: [&str; 6] = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
const ARGREGS8: [&str; 6] = ["dil", "sil", "dl", "cl", "r8b", "r9b"];
const ARGREGS32: [&str; 6] = ["edi", "esi", "edx", "ecx", "r8d", "r9d"];

lazy_static! {
    static ref LABEL: Mutex<usize> = Mutex::new(0);
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
    r15
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
        _ => panic!("index out of bounds")
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
        1 => REGS8[r],
        4 => REGS32[r],
        8 => regs(r),
        _ => unreachable!(),
    }
}

fn argreg(r: usize, size: u8) -> &'static str {
    match size {
        1 => ARGREGS8[r],
        4 => ARGREGS32[r],
        8 => ARGREGS[r],
        _ => unreachable!(),
    }
}

fn gen(f: Function, obfuscate_inst: &Vec<&str>) {
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
                if obfuscate_inst.iter().any(|&i| i == "imm" || i == "*") {
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
                if obfuscate_inst.iter().any(|&i| i == "mov" || i == "*") {
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
            },
            Return => {
                emit!("mov rax, {}", regs(lhs));
                if obfuscate_inst.iter().any(|&i| i == "ret" || i == "*") {
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
                    emit!("mov {}, {}", ARGREGS[i], regs(args[i]));
                }
                emit!("push r10");
                emit!("push r11");
                emit!("mov rax, 0");
                if obfuscate_inst.iter().any(|&i| i == "call" || i == "*") {
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
                if obfuscate_inst.iter().any(|&i| i == "lea" || i == "*") {
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
            },
            Neg => {
                if obfuscate_inst.iter().any(|&i| i == "neg" || i == "*") {
                    emit!("sub rsp, 0x10");
                    emit!("push rax");
                    emit!("lea rax, .Lgadget_neg_{}", regs(lhs));
                    emit!("mov [rsp+8], rax");
                    emit!("lea rax, .Lcall_gadget_{}_{}", f.name, call_gadget_id);
                    emit!("mov [rsp+0x10], rax");
                    emit!("pop rax");
                    emit!("ret");
                    println!(".Lcall_gadget_{}_{}:", f.name, call_gadget_id);
                    call_gadget_id += 1;
                } else  {
                    emit!("neg {}", regs(lhs));
                }
            },
            EQ => {
                if obfuscate_inst.iter().any(|&i| i == "cmp" || i == "*")      {
                    emit!("sub rsp, 0x10");
                    emit!("push rax");
                    emit!("lea rax, .Lgadget_sete_{}", REGS8[lhs]);
                    emit!("mov [rsp+8], rax");
                    emit!("lea rax, .Lcall_gadget_{}_{}", f.name, call_gadget_id);
                    emit!("mov [rsp+0x10], rax");
                    emit!("pop rax");
                    emit!("cmp {}, {}", regs(lhs), regs(rhs));
                    emit!("ret");
                    println!(".Lcall_gadget_{}_{}:", f.name, call_gadget_id);
                    emit!("movzb {}, {}", regs(lhs), REGS8[lhs]);
                    call_gadget_id += 1;
                } else {
                    emit!("cmp {}, {}", regs(lhs), regs(rhs));
                    emit!("sete {}", REGS8[lhs]);
                    emit!("movzb {}, {}", regs(lhs), REGS8[lhs]);
                }
            }, 
            NE => {
                if obfuscate_inst.iter().any(|&i| i == "cmp" || i == "*")      {
                    emit!("sub rsp, 0x10");
                    emit!("push rax");
                    emit!("lea rax, .Lgadget_setne_{}", REGS8[lhs]);
                    emit!("mov [rsp+8], rax");
                    emit!("lea rax, .Lcall_gadget_{}_{}", f.name, call_gadget_id);
                    emit!("mov [rsp+0x10], rax");
                    emit!("pop rax");
                    emit!("cmp {}, {}", regs(lhs), regs(rhs));
                    emit!("ret");
                    println!(".Lcall_gadget_{}_{}:", f.name, call_gadget_id);
                    emit!("movzb {}, {}", regs(lhs), REGS8[lhs]);
                    call_gadget_id += 1;
                } else {
                    emit!("cmp {}, {}", regs(lhs), regs(rhs));
                    emit!("setne {}", REGS8[lhs]);
                    emit!("movzb {}, {}", regs(lhs), REGS8[lhs]);
                }
            },
            LT => {
                if obfuscate_inst.iter().any(|&i| i == "cmp" || i == "*")      {
                    emit!("sub rsp, 0x10");
                    emit!("push rax");
                    emit!("lea rax, .Lgadget_setl_{}", REGS8[lhs]);
                    emit!("mov [rsp+8], rax");
                    emit!("lea rax, .Lcall_gadget_{}_{}", f.name, call_gadget_id);
                    emit!("mov [rsp+0x10], rax");
                    emit!("pop rax");
                    emit!("cmp {}, {}", regs(lhs), regs(rhs));
                    emit!("ret");
                    println!(".Lcall_gadget_{}_{}:", f.name, call_gadget_id);
                    emit!("movzb {}, {}", regs(lhs), REGS8[lhs]);
                    call_gadget_id += 1;
                } else {
                    emit!("cmp {}, {}", regs(lhs), regs(rhs));
                    emit!("setl {}", REGS8[lhs]);
                    emit!("movzb {}, {}", regs(lhs), REGS8[lhs]);
                }
            },
            LE => {
                if obfuscate_inst.iter().any(|&i| i == "cmp" || i == "*")      {
                    emit!("sub rsp, 0x10");
                    emit!("push rax");
                    emit!("lea rax, .Lgadget_setle_{}", REGS8[lhs]);
                    emit!("mov [rsp+8], rax");
                    emit!("lea rax, .Lcall_gadget_{}_{}", f.name, call_gadget_id);
                    emit!("mov [rsp+0x10], rax");
                    emit!("pop rax");
                    emit!("cmp {}, {}", regs(lhs), regs(rhs));
                    emit!("ret");
                    println!(".Lcall_gadget_{}_{}:", f.name, call_gadget_id);
                    emit!("movzb {}, {}", regs(lhs), REGS8[lhs]);
                    call_gadget_id += 1;
                } else {
                    emit!("cmp {}, {}", regs(lhs), regs(rhs));
                    emit!("setle {}", REGS8[lhs]);
                    emit!("movzb {}, {}", regs(lhs), REGS8[lhs]);
                }
            },
            AND => {
                emit!("and {}, {}", regs(lhs), regs(rhs))
            },
            OR => {
                emit!("or {}, {}", regs(lhs), regs(rhs))
            },
            XOR => {
                emit!("xor {}, {}", regs(lhs), regs(rhs))
            },
            SHL => {
                emit!("mov cl, {}", REGS8[rhs]);
                emit!("shl {}, cl", regs(lhs));
            }
            SHR => {
                emit!("mov cl, {}", REGS8[rhs]);
                emit!("shr {}, cl", regs(lhs));
            }
            Mod => {
                /* Same meaning(?).
                 * emit!("mov rdx, 0");
                 * emit!("mov rax, {}", regs(lhs]);
                 */
                emit!("mov rax, {}", regs(lhs));
                emit!("cqo"); // rax -> rdx:rax
                emit!("div {}", regs(rhs));
                emit!("mov {}, rdx", regs(lhs));
            }
            Jmp => {
                if obfuscate_inst.iter().any(|&i| i == "jmp" || i == "*") {
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
                emit!("mov {}, [{}]", reg(lhs, size), regs(rhs));
                if size == 1 {
                    emit!("movzb {}, {}", regs(lhs), REGS8[lhs]);
                }
            }
            Store(size) => emit!("mov [{}], {}", regs(lhs), reg(rhs, size)),
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

    if obfuscate_inst.iter().any(|&i| i == "imm"|| i == "mov" || i == "*") {
        println!(".text");
        for i in 0..REGS_N{
            println!(".Lgadget_mov_{}:", regs(i));
            emit!("pop {}", regs(i));
            emit!("ret");
        }
    }

    if obfuscate_inst.iter().any(|&i| i == "lea" || i == "*") {
        println!(".text");
        for i in 0..REGS_N {
            println!(".Lgadget_lea_{}:", regs(i));
            emit!("pop {}", regs(i));
            emit!("ret");
        }
    }

    if obfuscate_inst.iter().any(|&i| i == "neg" || i == "*") {
        println!(".text");
        for i in 0..REGS_N {
            println!(".Lgadget_neg_{}:", regs(i));
            emit!("neg {}", regs(i));
            emit!("ret");
        }
    }

    if obfuscate_inst.iter().any(|&i| i == "cmp" || i == "*") {
        println!(".text");
        for reg in REGS8.iter() {
            println!(".Lgadget_sete_{}:", reg);
            emit!("sete {}", reg);
            emit!("ret");
            println!(".Lgadget_setne_{}:", reg);
            emit!("setne {}", reg);
            emit!("ret");
            println!(".Lgadget_setl_{}:", reg);
            emit!("setl {}", reg);
            emit!("ret");
            println!(".Lgadget_setle_{}:", reg);
            emit!("setle {}", reg);
            emit!("ret");
        }

    }

    for f in fns {
        gen(f, &obfuscate_inst);
    }
}
