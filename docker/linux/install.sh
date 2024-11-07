if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# Build Dependencies; # WSL2 won't work with linux headers, fallback to generic
apt update && \
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
    zip \
    dotnet-sdk-8.0 \
    sudo
    
# Originally was grouped with install dotnet
chown -R root:root /var/lib

# Install Rust
apt install curl
(curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh -s -- -y)
PATH="/root/.cargo/bin:${PATH}"
. "$HOME/.cargo/env"
rustup update "$RUST_VERSION"
rustup component add rust-std-x86_64-unknown-linux-musl
rustup default "$RUST_VERSION"
