#!/bin/sh

echo "=== Cross-compiling: ============================="
make CC=riscv64-unknown-elf-gcc CFLAGS=-march=rv64gc benchmark

echo "=== rsync with RISC-V host ======================="
rsync -av --exclude='*.*' --progress --stats ./build/  paulopacitti@192.168.6.38:/home/paulopacitti/workspaces/ascon-v

echo "=== perf on RISC-V host =========================="
ssh -T paulopacitti@192.168.6.38 << "ENDSSH"
    cd /home/paulopacitti/workspaces/ascon-v
    ./benchmark
ENDSSH