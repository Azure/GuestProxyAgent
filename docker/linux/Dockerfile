FROM ubuntu:latest

ARG RUST_VERSION

COPY install.sh ./
RUN chmod +x install.sh
RUN RUST_VERSION=$RUST_VERSION ./install.sh
