FROM ubuntu:22.04
LABEL maintainer="paulopacitti"

# Install dependencies
RUN apt -y update \
    && apt install -y autoconf automake autotools-dev curl \
    libmpc-dev libmpfr-dev libgmp-dev \
    python3 pkg-config libglib2.0-dev libpixman-1-dev gawk \
    build-essential bison flex texinfo gperf libtool patchutils \
    bc zlib1g-dev libexpat-dev git ninja-build \
    && rm -rf /var/lib/apt/lists/*

# Clone QEMU repo
WORKDIR /tmp
RUN mkdir riscv-qemu-linux \ 
    && cd riscv-qemu-linux \
    && git clone --depth=1 --branch=stable-8.0 https://github.com/qemu/qemu

# Build QEMU with system mode RISC-V emulation 
WORKDIR /tmp/riscv-qemu-linux/qemu
RUN ./configure --target-list=riscv32-softmmu,riscv64-softmmu \
    && make -j $(nproc) \
    && make install \
    && make clean
# Build user mode RISC-V QEMU
RUN mkdir -p /opt/qemu-riscv-static \
    && ./configure --target-list=riscv32-linux-user,riscv64-linux-user \
    --static \
    --disable-system \
    --enable-linux-user \
    --prefix=/opt/qemu-riscv-static \
    && make -j $(nproc) \
    && make install \
    && make clean \
    && rm -rf /tmp/riscv-qemu-linux/qemu

# Create symbolic links for user mode RISC-V QEMU
RUN ln -s /opt/qemu-riscv-static/bin/qemu-riscv64 /usr/local/bin/qemu-riscv64 \ 
    && ln -s /opt/qemu-riscv-static/bin/qemu-riscv32 /usr/local/bin/qemu-riscv32

ENV LC_CTYPE C.UTF-8
WORKDIR /root