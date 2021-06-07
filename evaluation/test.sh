#!/bin/bash
for inst in "call" "jmp" "ret" "imm" "mov" "lea" "cmp" "neg" "and" "or" "xor" "shift" "mod"
do
    ../target/release/r9cc src.c -i $inst > prime_$inst.s; gcc -no-pie prime_$inst.s -o prime_$inst;
done

echo "compile done";

hyperfine --warmup 5 "./prime_call" "./prime_jmp" "./prime_ret" "./prime_imm" "./prime_mov" "./prime_lea" "./prime_cmp" "./prime_neg" "./prime_and" "./prime_or" "./prime_xor" "./prime_shift" "./prime_mod"
