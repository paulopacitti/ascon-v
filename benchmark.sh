#!/bin/sh

echo "=== Cross-compiling: ============================="
make CC=riscv64-unknown-elf-gcc
echo "=== rsync with RISC-V host ======================="
rsync -av --exclude='*.*' ./build/  paulopacitti@192.168.6.38:/home/paulopacitti/workspaces/ascon-v
echo "=== perf on RISC-V host =========================="
ssh -T paulopacitti@192.168.6.38 << "ENDSSH"
    cd /home/paulopacitti/workspaces/ascon-v
    sudo perf stat ./test
ENDSSH