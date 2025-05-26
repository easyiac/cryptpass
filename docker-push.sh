#!/usr/bin/env bash
set -euo pipefail

version=$(cargo metadata --format-version=1 --no-deps | jq '.packages.[0].version' -c -r)
rust_version=$(cargo metadata --format-version=1 --no-deps | jq '.packages.[0].rust_version' -c -r)
docker buildx create --name cryptpass-builder --driver docker-container --bootstrap \
    --buildkitd-config buildkitd.toml || true

docker buildx build -f Dockerfile . \
    --builder cryptpass-builder \
    --build-arg RUST_VERSION="${rust_version}" \
    -t "docker.io/arpanrecme/cryptpass:${version}" \
    -t "docker.io/arpanrecme/cryptpass:latest" \
    -t "10.8.33.192:8008/cryptpass/cryptpass:${version}" \
    -t "10.8.33.192:8008/cryptpass/cryptpass:latest" \
    --platform linux/amd64,linux/arm64 \
    --output type=registry \
    --progress=plain --network=none
