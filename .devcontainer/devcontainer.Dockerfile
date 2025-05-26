FROM mcr.microsoft.com/devcontainers/rust:1-1-bookworm

RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y ca-certificates curl git

RUN ls -altrh

RUN mkdir -p /usr/local/share/ca-certificates
COPY root_ca_crt.pem /usr/local/share/ca-certificates/root_ca_crt.crt
RUN update-ca-certificates
