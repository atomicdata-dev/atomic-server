VERSION 0.7
PROJECT applied-knowledge-systems/atomic-server
# You can compile front end separately and copy dist folder
# IMPORT ./browser AS browser
FROM rust:latest
WORKDIR /code

main-pipeline:
  PIPELINE --push 
  TRIGGER push main 
  TRIGGER pr main 
  ARG tag=latest
  BUILD +build --tag=$tag

deps:
  RUN curl -fsSL https://bun.sh/install | bash
  RUN  /root/.bun/bin/bun install -y pnpm
  # COPY . .
  COPY --dir server lib cli desktop Cargo.lock Cargo.toml .
  # RUN mkdir src
  # RUN touch src/main.rs # adding main.rs stub so cargo fetch works to prepare the cache
  RUN cargo fetch 

test:
  FROM +deps
  RUN cargo test

build:
  FROM +deps
  RUN rustup target add x86_64-unknown-linux-musl
  RUN apt update && apt install -y musl-tools musl-dev
  RUN update-ca-certificates
  WORKDIR /app
  # FIXME: Joep you need to fix this line and modify Earthfile inside browser
  # COPY browser+build/dist ./public
  COPY --dir server lib cli desktop Cargo.lock Cargo.toml .
  RUN cargo build --release --bin atomic-server --config net.git-fetch-with-cli=true --target x86_64-unknown-linux-musl
  RUN strip -s /app/target/x86_64-unknown-linux-musl/release/atomic-server
  SAVE ARTIFACT /app/target/x86_64-unknown-linux-musl/release/atomic-server

docker:
    # We only need a small runtime for this step, but make sure glibc is installed
    FROM scratch
    COPY --chmod=0755 +build/atomic-server /atomic-server-bin
    # For a complete list of possible ENV vars or available flags, run with `--help`
    ENV ATOMIC_STORE_PATH="/atomic-storage/db"
    ENV ATOMIC_CONFIG_PATH="/atomic-storage/config.toml"
    ENV ATOMIC_PORT="80"
    EXPOSE 80
    VOLUME /atomic-storage
    ENTRYPOINT ["/atomic-server-bin"]
    SAVE IMAGE --push ghcr.io/applied-knowledge-systems/atomic-server:edge
