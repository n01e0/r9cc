#[macro_use]
extern crate clap;
extern crate r9cc;

use r9cc::gen_ir::gen_ir;
use r9cc::gen_x86::gen_x86;
use r9cc::irdump::dump_ir;
use r9cc::parse::parse;
use r9cc::preprocess::Preprocessor;
use r9cc::regalloc::alloc_regs;
use r9cc::sema::sema;
use r9cc::token::tokenize;

fn main() {
    let yml = load_yaml!("cmd.yml");
    let args = clap::App::from_yaml(yml).get_matches();

    let mut dump_ir1 = false;
    let mut dump_ir2 = false;
    if args.is_present("dump") {
        dump_ir1 = args.value_of("dump").unwrap() == "1";
        dump_ir2 = args.value_of("dump").unwrap() == "2";
    }
    let path = args.value_of("path").unwrap().to_string();
    let obfuscate_inst = args.values_of("inst").unwrap().collect::<Vec<_>>();

    // Tokenize and parse.
    let tokens = tokenize(path, &mut Preprocessor::new());

    let nodes = parse(&tokens);
    let (nodes, globals) = sema(nodes);
    let mut fns = gen_ir(nodes);

    if dump_ir1 {
        dump_ir(&fns);
    }

    alloc_regs(&mut fns);

    if dump_ir2 {
        dump_ir(&fns);
    }

    gen_x86(globals, fns, obfuscate_inst);
}
