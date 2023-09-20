# when cross-compiling, set the proper RISC-V compiler in CC

CC=gcc
ifeq ($(shell uname -s), Darwin)
CC=clang
endif
TESTS=tests
BUILD=build

all: $(BUILD) test

test: tests/aead_test.c $(BUILD)/asconv.o $(BUILD)/Unity.o
	$(CC) $^ -Wall -g -o $(BUILD)/test

$(BUILD)/asconv.o: src/asconv.c src/asconv.h $(BUILD)
	$(CC) -c src/asconv.c -o $(BUILD)/asconv.o

$(BUILD)/Unity.o: $(BUILD)
	$(CC) -c lib/Unity/unity.c -o $(BUILD)/Unity.o

$(BUILD):
	mkdir -p build

clean:
	rm -rf $(BUILD)
