#!/usr/bin/env bash
set -euo pipefail

version=$(cat CRYPTPASS_VERSION)

docker buildx create --name cryptpass-builder --driver docker-container --bootstrap || true

docker buildx build -f Dockerfile . \
    --builder cryptpass-builder \
    -t "docker.io/arpanrecme/cryptpass:${version}" \
    -t "docker.io/arpanrecme/cryptpass:rust" \
    -t "docker.io/arpanrecme/cryptpass:rust-${version}" \
    -t "docker.io/arpanrecme/cryptpass:latest" \
    --platform linux/amd64,linux/arm64 \
    --output type=registry \
    --network=none
