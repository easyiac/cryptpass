#!/usr/bin/env bash
set -euo pipefail

log_message() {
    printf "\n\n================================================================================\n %s \
Setup Cryptpass: \
%s\n--------------------------------------------------------------------------------\n\n" "$(date)" "$*"
}

touch CRYPTPASS_VERSION

tee "/tmp/cryptpass-build.Dockerfile" <<EOF
FROM docker.io/library/rust:1.86.0-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross

RUN rustup target add aarch64-unknown-linux-gnu
RUN rustup target add x86_64-unknown-linux-gnu

WORKDIR /src
COPY . .
EOF

docker buildx build -f /tmp/cryptpass-build.Dockerfile -t cryptpass-builder:1 .

docker run --rm \
    -v "$(pwd)/target/:/src/target/" \
    -v "$(pwd)/CRYPTPASS_VERSION:/src/CRYPTPASS_VERSION" \
    -e CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    -e CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    -e CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
    cryptpass-builder:1 \
    /bin/bash -c "cargo build -j $(nproc) --release --target aarch64-unknown-linux-gnu"

docker run --rm \
    -v "$(pwd)/target/:/src/target/" \
    -v "$(pwd)/CRYPTPASS_VERSION:/src/CRYPTPASS_VERSION" \
    cryptpass-builder:1 \
    /bin/bash -c "cargo build -j $(nproc) --release --target x86_64-unknown-linux-gnu"

sudo chown -R "$(id -u)":"$(id -g)" target CRYPTPASS_VERSION

log_message "Installing required collections and roles"
uv pip install -e .
uv run ansible-galaxy collection install community.general
uv run ansible-galaxy collection install community.docker
uv run ansible-galaxy role install geerlingguy.docker
uv run ansible-playbook ansible/playbook.yml
