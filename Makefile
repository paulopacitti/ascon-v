CC=gcc
ifeq ($(shell uname -s), Darwin)
CC=clang
endif
CC-CROSS-COMPILER=riscv64-unknown-elf-gcc
TESTS=tests

all: test

test: tests/aead_test.c
	$(CC) tests/aead_test.c -o $(TESTS)/test
	./$(TESTS)/test

clean:
	rm -rf $(TESTS)/test
	rm -rf $(BUILD)
