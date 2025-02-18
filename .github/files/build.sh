#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update &&
    sudo apt-get install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross

rustup target add aarch64-unknown-linux-gnu
rustup target add x86_64-unknown-linux-gnu

mkdir -p /tmp/crustpass && rm -rf /tmp/crustpass/aarch64*

echo "Building crustpass for aarch64"
env CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
    cargo build --target aarch64-unknown-linux-gnu --release
mv ./target/aarch64-unknown-linux-gnu/release/crustpass /tmp/crustpass/crustpass-linux-aarch64
aarch64_256sum=$(sha256sum /tmp/crustpass/crustpass-linux-aarch64 | cut -d ' ' -f 1)
echo "${aarch64_256sum} crustpass-linux-aarch64" | tee -a /tmp/crustpass/sha256.txt

echo "Building crustpass for x86_64"
cargo build --target x86_64-unknown-linux-gnu --release
mv ./target/x86_64-unknown-linux-gnu/release/crustpass /tmp/crustpass/crustpass-linux-x86_64
x86_64_256sum=$(sha256sum /tmp/crustpass/crustpass-linux-x86_64 | cut -d ' ' -f 1)
echo "${x86_64_256sum} crustpass-linux-x86_64" | tee -a /tmp/crustpass/sha256.txt
