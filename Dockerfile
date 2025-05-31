# syntax=docker/dockerfile:experimental
ARG RUST_VERSION=0.0.0
FROM docker.io/library/rust:${RUST_VERSION}-bookworm AS builder

WORKDIR /src

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --bin cryptpass

# Because the target directory is not available in the final image out side of the cache mount.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cp /src/target/release/cryptpass /src/cryptpass

# In order to clean the cache
# docker builder prune --filter type=exec.cachemount

FROM docker.io/library/debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
COPY --from=builder /src/cryptpass /usr/local/bin/cryptpass
#RUN apt-get update && apt-get install -y libsqlite3-dev # libsqlite3-sys = { version = "0.33.0", features = ["bundled", "cc"] }
CMD [ "/usr/local/bin/cryptpass" ]
