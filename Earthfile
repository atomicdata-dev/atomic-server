VERSION 0.7
PROJECT ontola/atomic-server
IMPORT ./browser AS browser
FROM rust:latest
WORKDIR /code

main-pipeline:
  PIPELINE --push
  TRIGGER push develop
  TRIGGER push main
  TRIGGER pr develop
  ARG tag=latest
  BUILD +test
  BUILD +clippy
  BUILD +build --tag=$tag

deps:
  COPY --dir server lib cli desktop Cargo.lock Cargo.toml .
  RUN cargo fetch

test:
  FROM +deps
  RUN cargo test

clippy:
  FROM +deps
  RUN cargo clippy --no-deps

build:
  FROM +deps
  RUN rustup target add x86_64-unknown-linux-musl
  RUN apt update && apt install -y musl-tools musl-dev g++-x86-64-linux-gnu libc6-dev-amd64-cross
  RUN update-ca-certificates
  WORKDIR /app
  COPY browser+build/data-browser/dist /app/browser/data-browser/dist
  COPY --dir server lib cli desktop Cargo.lock Cargo.toml .
  RUN cargo build --release --bin atomic-server --config net.git-fetch-with-cli=true --target x86_64-unknown-linux-musl
  RUN strip -s /app/target/x86_64-unknown-linux-musl/release/atomic-server
  SAVE ARTIFACT /app/target/x86_64-unknown-linux-musl/release/atomic-server

docker:
  COPY --chmod=0755 +build/atomic-server /atomic-server-bin
  # For a complete list of possible ENV vars or available flags, run with `--help`
  ENV ATOMIC_STORE_PATH="/atomic-storage/db"
  ENV ATOMIC_CONFIG_PATH="/atomic-storage/config.toml"
  ENV ATOMIC_PORT="80"
  EXPOSE 80
  VOLUME /atomic-storage
  ENTRYPOINT ["/atomic-server-bin"]
  SAVE IMAGE --push ghcr.io/atomicdata-dev/atomic-server:latest

e2e:
  FROM mcr.microsoft.com/playwright:v1.38.0-jammy
  RUN curl -f https://get.pnpm.io/v6.14.js | node - add --global pnpm
  RUN pnpx playwright install --with-deps
  COPY browser/ /app
  WORKDIR app
  ENV FRONTEND_URL="http://localhost"
  ENV LANGUAGE="en_GB"
  RUN pnpm install
  RUN pnpm playwright-install
  WITH DOCKER \
    --load test:latest=+docker
    RUN docker run -d -p 80:80 test:latest  & \
    pnpm run test-e2e
  END
