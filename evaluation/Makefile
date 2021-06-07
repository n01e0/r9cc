all: prime nqueen fib

r9cc = ../target/release/r9cc

build: ../src/ ../Cargo.toml
	cargo build --release

prime: build prime.c
	@$(r9cc) prime.c > prime_default.s 2>/dev/null
	@gcc prime_default.s -no-pie -o prime_default
	@for inst in "call" "jmp" "ret" "mov" "lea" "cmp" "neg" "and" "or" "xor" "shift" "mod" "all"; do\
		$(r9cc)	prime.c -i $$inst > prime_$$inst.s 2>/dev/null;\
		gcc prime_$$inst.s -no-pie -o prime_$$inst;\
	done

prime_bench: prime
	hyperfine --warmup 3 "./prime_default" "./pime_call" "./prime_jmp" "./prime_ret" "./prime_mov" "./prime_lea" "./prime_cmp" "./prime_neg" "./prime_and" "./prime_or" "./prime_xor" "./prime_shift" "./prime_mod" "./prime_all"

nqueen: build nqueen.c
	@$(r9cc) nqueen.c > nqueen_default.s 2>/dev/null
	@gcc nqueen_default.s -no-pie -o nqueen_default 
	@for inst in "call" "jmp" "ret" "mov" "lea" "cmp" "neg" "and" "or" "xor" "shift" "mod" "all"; do\
		$(r9cc)	nqueen.c -i $$inst > nqueen_$$inst.s 2>/dev/null;\
		gcc nqueen_$$inst.s -no-pie -o nqueen_$$inst;\
	done

nqueen_bench: nqueen
	hyperfine --warmup 3 "./nqueen_default" "./pime_call" "./nqueen_jmp" "./nqueen_ret" "./nqueen_mov" "./nqueen_lea" "./nqueen_cmp" "./nqueen_neg" "./nqueen_and" "./nqueen_or" "./nqueen_xor" "./nqueen_shift" "./nqueen_mod" "./nqueen_all"

fib: build fib.c
	@$(r9cc) fib.c > fib_default.s 2>/dev/null
	@gcc fib_default.s -no-pie -o fib_default 
	@for inst in "call" "jmp" "ret" "mov" "lea" "cmp" "neg" "and" "or" "xor" "shift" "mod" "all"; do\
		$(r9cc)	fib.c -i $$inst > fib_$$inst.s 2>/dev/null;\
		gcc fib_$$inst.s -no-pie -o fib_$$inst;\
	done

fib_bench: fib
	hyperfine --warmup 3 "./fib_default" "./pime_call" "./fib_jmp" "./fib_ret" "./fib_mov" "./fib_lea" "./fib_cmp" "./fib_neg" "./fib_and" "./fib_or" "./fib_xor" "./fib_shift" "./fib_mod" "./fib_all"

all_bench: prime nqueen fib
	hyperfine --warmup 3 "./prime_default" "./pime_call" "./prime_jmp" "./prime_ret" "./prime_mov" "./prime_lea" "./prime_cmp" "./prime_neg" "./prime_and" "./prime_or" "./prime_xor" "./prime_shift" "./prime_mod" "./prime_all"
	hyperfine --warmup 3 "./nqueen_default" "./pime_call" "./nqueen_jmp" "./nqueen_ret" "./nqueen_mov" "./nqueen_lea" "./nqueen_cmp" "./nqueen_neg" "./nqueen_and" "./nqueen_or" "./nqueen_xor" "./nqueen_shift" "./nqueen_mod" "./nqueen_all"
	hyperfine --warmup 3 "./fib_default" "./pime_call" "./fib_jmp" "./fib_ret" "./fib_mov" "./fib_lea" "./fib_cmp" "./fib_neg" "./fib_and" "./fib_or" "./fib_xor" "./fib_shift" "./fib_mod" "./fib_all"


clean:
	@rm -f *.s prime_* nqueen_* fib_*
