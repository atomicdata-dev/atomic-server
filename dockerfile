FROM rust:1.67 AS builder
# Install musl dependencies
RUN rustup target add x86_64-unknown-linux-musl
RUN apt update && apt install -y musl-tools musl-dev
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
