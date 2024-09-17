FROM ubuntu:latest

ARG RUST_VERSION

# Build Dependencies; # WSL2 won't work with linux headers, fallback to generic
RUN apt update && \
    (apt install linux-headers-$(uname -r) linux-tools-$(uname -r) || (apt install -y linux-headers-generic && exit 0)) \
    && apt install -y \
        git \
        libbpfcc-dev \
        libbpf-dev \
        llvm \
        clang \
        gcc-multilib \
        build-essential \
        linux-tools-common \
        linux-tools-generic \
        rpm \
        musl-tools \
        zip

# Install dotnet
RUN apt install -y dotnet-sdk-8.0
RUN chown -R root:root /var/lib

# Test Dependencies
RUN apt install sudo

# Install Rust
RUN apt install curl
RUN (curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh -s -- -y)
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup update $RUST_VERSION
RUN rustup component add rust-std-x86_64-unknown-linux-musl
RUN rustup default $RUST_VERSION
