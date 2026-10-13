# syntax=docker/dockerfile:1
#
# Build image for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner).
#
# The scanner builds this image WITH internet access and then scans the result
# WITHOUT internet, so everything must be fetched here: the Rust toolchain
# pinned in rust-toolchain.toml, the wasm targets, wasm-pack (via tools/cargo-bin),
# every crate (`cargo fetch`), every node module (`pnpm install`), and the
# compiled debug artifacts, so `cargo test --offline` works in the built image.
#
# Build context: the repository root.
#   docker build -f .oss-scanner/Dockerfile -t atomic-server-scan .
#
# Mirrors .claude/hooks/cloud-setup.sh + cloud-build.sh, which are the tested
# source of truth for the toolchain steps. If they change, update this file.
FROM debian:bookworm

ARG NODE_VERSION=22.16.0
ARG PNPM_VERSION=11.10.0
ARG BINARYEN_VERSION=version_117

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/node/bin:$PATH \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    CI=true

# Native build dependencies for the Rust workspace (openssl, ring, lancedb-free
# default features) and for downloading the toolchains.
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
      ca-certificates curl git xz-utils tar unzip \
      build-essential pkg-config libssl-dev cmake clang nasm protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Node (the repo CI uses Node 22) and the pnpm version pinned in
# browser/package.json "packageManager".
RUN set -eux; \
    arch="$(uname -m)"; case "$arch" in x86_64) n=x64;; aarch64) n=arm64;; *) echo "unsupported arch $arch" >&2; exit 1;; esac; \
    curl -fsSL --retry 3 "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${n}.tar.xz" -o /tmp/node.tar.xz; \
    mkdir -p /usr/local/node; \
    tar -xJf /tmp/node.tar.xz -C /usr/local/node --strip-components=1; \
    rm /tmp/node.tar.xz; \
    npm install -g "pnpm@${PNPM_VERSION}"; \
    node --version; pnpm --version

# binaryen's wasm-opt, used by wasm-pack (same version as cloud-setup.sh).
RUN set -eux; \
    case "$(uname -m)" in x86_64) b=x86_64-linux;; aarch64) b=aarch64-linux;; *) exit 1;; esac; \
    curl -fsSL --retry 3 "https://github.com/WebAssembly/binaryen/releases/download/${BINARYEN_VERSION}/binaryen-${BINARYEN_VERSION}-${b}.tar.gz" \
      | tar -xz -C /opt; \
    ln -s "/opt/binaryen-${BINARYEN_VERSION}/bin/wasm-opt" /usr/local/bin/wasm-opt; \
    wasm-opt --version

# Source. Copied after the system setup so those layers stay cached.
WORKDIR /src
COPY . /src

# Rust toolchain exactly as pinned in rust-toolchain.toml, plus the two wasm
# targets: wasm32-unknown-unknown (browser WASM) and wasm32-wasip2 (the plugin
# runtime that server/build_plugin_runtime.rs embeds).
RUN set -eux; \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none; \
    RUST_VERSION="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)"; \
    rustup toolchain install "$RUST_VERSION" --profile minimal \
      --component rustfmt --component clippy \
      --target wasm32-unknown-unknown --target wasm32-wasip2; \
    rustup default "$RUST_VERSION"; \
    rustc --version; cargo --version

# Fetch every crate in the workspace (including dev-dependencies and the crates
# for tools/cargo-bin, which compiles wasm-pack), so nothing needs the network
# once the image is built.
RUN cargo fetch --locked

# Node dependencies for the whole browser/ workspace.
RUN cd browser && pnpm install --frozen-lockfile

# Build. server/build.rs runs `pnpm run build` in browser/ (which invokes
# wasm-pack through tools/cargo-bin and builds the data-browser and form-app
# bundles) and builds the wasm32-wasip2 plugin runtime, then embeds both.
# A debug build is used: it is what the repo's own test suites run against
# (browser/lib integration tests expect target/debug/atomic-server).
RUN cargo build --locked -p atomic-server

# Compile the Rust test binaries now (this is the expensive part) so the scan
# can run `cargo test --offline` without network or a cold compile.
# `atomic_lib` unit tests need the `db-redb` feature, which atomic-server turns
# on through feature unification.
RUN cargo test --locked -p atomic_lib -p atomic-server --no-run

# The scanner has no network. Make Cargo and pnpm fail fast instead of
# attempting downloads.
ENV CARGO_NET_OFFLINE=true \
    npm_config_offline=true

# Run the server tests offline:
#   cargo test --offline -p atomic_lib --features db-redb --lib
#   cargo test --offline -p atomic-server --lib
# Start the server (HTTP/WS on 9883; ATOMIC_IP=0.0.0.0 avoids IPv6 binding
# problems in containers):
#   ATOMIC_IP=0.0.0.0 /src/target/debug/atomic-server --initialize
WORKDIR /src
CMD ["/src/target/debug/atomic-server", "--help"]
