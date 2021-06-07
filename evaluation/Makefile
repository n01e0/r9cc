all: prime

r9cc = ../target/release/r9cc

build: ../src/ ../Cargo.toml
	cargo build --release

prime: build prime.c
	@$(r9cc) prime.c > prime_default.s 2>/dev/null
	@gcc prime_default.s -no-pie -o prime
	@for inst in "call" "jmp" "ret" "mov" "lea" "cmp" "neg" "and" "or" "xor" "shift" "mod" "all"; do\
		$(r9cc)	prime.c -i $$inst > prime_$$inst.s 2>/dev/null;\
		gcc prime_$$inst.s -no-pie -o prime_$$inst;\
	done

prime_bench: prime
	hyperfine --warmup 3 "./prime_default" "./pime_call" "./prime_jmp" "./prime_ret" "./prime_mov" "./prime_lea" "./prime_cmp" "./prime_neg" "./prime_and" "./prime_or" "./prime_xor" "./prime_shift" "./prime_mod" "./prime_all"

clean:
	rm -f *.s prime_*
