#!/bin/bash
for inst in "call" "jmp" "ret" "mov" "lea" "cmp" "neg" "and" "or" "xor" "shift" "mod"
do
    echo $inst replaced `rg $inst prime.s|wc -l` times;
done
