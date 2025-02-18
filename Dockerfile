FROM docker.io/library/rust:1.84.1-bullseye AS builder

RUN apt-get update && apt-get install -y cmake

WORKDIR /usr/src/app

COPY . .

RUN cargo build --release

FROM docker.io/library/debian:bullseye-slim

COPY --from=builder /usr/src/app/target/release/crustpass /usr/local/bin/crustpass

CMD ["/usr/local/bin/crustpass"]
