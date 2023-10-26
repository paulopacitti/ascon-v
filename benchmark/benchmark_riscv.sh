#!/bin/sh

echo "=== Cross-compiling: ============================="
make CC=riscv64-unknown-elf-gcc CFLAGS="-Wall -march=rv64gc -mtune=thead-c906 -O2" benchmark

echo "=== rsync with RISC-V host ======================="
rsync -av --exclude='*.*' --progress --stats ./build/  paulopacitti@192.168.6.38:/home/paulopacitti/workspaces/ascon-v

echo "=== perf on RISC-V host =========================="
ssh -T paulopacitti@192.168.6.38 << "ENDSSH"
    cd /home/paulopacitti/workspaces/ascon-v
    ./benchmark
ENDSSH