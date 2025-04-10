FROM docker.io/library/rust:1.86.0-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release

FROM docker.io/library/debian:bookworm
COPY --from=builder /src/target/release/cryptpass /usr/local/bin/cryptpass

CMD [ "/usr/local/bin/cryptpass" ]
