FROM clux/muslrust:stable AS builder
# Install musl dependencies
# RUN rustup target add x86_64-unknown-linux-musl

# Cross-compiling for musl requires some specific linkers due to ring
# https://github.com/briansmith/ring/issues/1414#issuecomment-1055177218
# RUN apt update && apt install -y musl-tools clang llvm musl-dev
# ENV RUSTFLAGS='-C linker=x86_64-linux-gnu-gcc'
# ENV CC_aarch64_unknown_linux_musl=clang
# ENV AR_aarch64_unknown_linux_musl=llvm-ar
# ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-Clink-self-contained=yes -Clinker=rust-lld"

WORKDIR /app
COPY . .
RUN cargo build --release --bin atomic-server --config net.git-fetch-with-cli=true --target x86_64-unknown-linux-musl
RUN strip -s /app/target/x86_64-unknown-linux-musl/release/atomic-server

FROM scratch as runtime
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/atomic-server /atomic-server-bin

# For a complete list of possible ENV vars or available flags, run with `--help`
ENV ATOMIC_STORE_PATH="/atomic-storage/db"
ENV ATOMIC_CONFIG_PATH="/atomic-storage/config.toml"
ENV ATOMIC_PORT="80"
EXPOSE 80
VOLUME /atomic-storage
ENTRYPOINT ["/atomic-server-bin"]
