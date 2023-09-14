CC=gcc
ifeq ($(shell uname -s), Darwin)
CC=clang
endif

CC-CROSS-COMPILER=riscv64-unknown-elf-gcc
TESTS=tests
BUILD=build

all: $(BUILD) test

test: tests/aead_test.c $(BUILD)/Unity.o  $(BUILD)/asconv.o 
	$(CC) $^ -o $(BUILD)/test
	./$(BUILD)/test

$(BUILD)/asconv.o: src/asconv.c src/asconv.h $(BUILD)
	$(CC) -c src/asconv.c -o $(BUILD)/asconv.o

$(BUILD)/Unity.o: $(BUILD)
	$(CC) -c lib/Unity/unity.c -o $(BUILD)/Unity.o

$(BUILD):
	mkdir -p build

clean:
	rm -rf $(BUILD)
