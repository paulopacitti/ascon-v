BUILD = build
COMPILER = /opt/riscv64/bin/riscv64-unknown-elf-gcc 
DEBUGGER = riscv64-unknown-elf-gdb
EMULATOR = qemu-system-riscv64
SIMULATOR = spike pk

all: main

clean:
	rm -rf main
	rm -rf $(BUILD)

main: src/main.c
	$(info [main] compile src/main.c:)
	$(COMPILER) src/main.c -static -o main.elf

debug: src/main.c
	$(info [main] compile for debugging src/main.c:)
	$(COMPILER) -g -static src/main.c -o main.elf