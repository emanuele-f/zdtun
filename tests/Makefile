.PHONY: clean run_tests

clean:
	rm -rf build

run_tests:
	mkdir -p build
	cd build && \
		cmake -DCMAKE_C_COMPILER=clang -DCMAKE_C_FLAGS="-fsanitize=address,undefined,leak -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g -O0" .. && \
		$(MAKE) run_tests
