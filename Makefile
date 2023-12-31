# when cross-compiling, set the proper RISC-V compiler in CC

CC=gcc
ifeq ($(shell uname -s), Darwin)
CC=clang
endif
TESTS=tests
BUILD=build
CFLAGS=-Wall -g

all: benchmark test

test: tests/aead_test.c $(BUILD)/asconv.o $(BUILD)/ref.o $(BUILD)/Unity.o
	$(CC) $^ $(CFLAGS) -o $(BUILD)/test

benchmark: benchmark/benchmark.c $(BUILD)/ref.o $(BUILD)/opt64.o $(BUILD)/asconv.o
	$(CC) $^ $(CFLAGS) -o $(BUILD)/benchmark

$(BUILD)/ref.o: $(BUILD) ref/aead.c
	$(CC) $(CFLAGS) -c ref/aead.c -o $(BUILD)/ref.o

$(BUILD)/opt64.o: $(BUILD) opt64/aead.c
	$(CC) $(CFLAGS) -c opt64/aead.c -o $(BUILD)/opt64.o

$(BUILD)/asconv.o: src/asconv.c src/asconv.h $(BUILD)
	$(CC) $(CFLAGS) -c src/asconv.c -o $(BUILD)/asconv.o

$(BUILD)/Unity.o: $(BUILD)
	$(CC) -c lib/Unity/unity.c -o $(BUILD)/Unity.o

$(BUILD):
	mkdir -p build

clean:
	rm -rf $(BUILD)
