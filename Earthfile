VERSION --try --global-cache 0.7
PROJECT ontola/atomic-server
IMPORT ./browser AS browser
IMPORT github.com/earthly/lib/rust:2.2.10 AS rust
FROM rust:1.73.0-buster
WORKDIR /code

pipeline:
  ARG tag=latest
  BUILD +fmt
  BUILD +lint
  BUILD +test
  BUILD +build
  BUILD +docker --tag=$tag
  BUILD +e2e

deps:
  # Install tools
  RUN rustup component add clippy
  # Atomic-Server deps
  RUN rustup target add x86_64-unknown-linux-musl
  RUN apt update && apt install -y musl-tools musl-dev g++-x86-64-linux-gnu libc6-dev-amd64-cross libgtk-3-dev libsoup2.4-dev
  # Tauri deps
  RUN apt install -y libwebkit2gtk-4.0-dev
  RUN update-ca-certificates

install:
  RUN apt-get update -qq
  RUN apt-get install --no-install-recommends -qq autoconf autotools-dev libtool-bin clang cmake bsdmainutils
  RUN rustup component add clippy
  RUN rustup component add rustfmt
  # Atomic-Server deps
  RUN rustup target add x86_64-unknown-linux-musl
  RUN apt update && apt install -y musl-tools musl-dev g++-x86-64-linux-gnu libc6-dev-amd64-cross libgtk-3-dev libsoup2.4-dev
  # Tauri deps
  RUN apt install -y libwebkit2gtk-4.0-dev
  RUN update-ca-certificates
  # Call +INIT before copying the source file to avoid installing depencies every time source code changes.
  # This parametrization will be used in future calls to UDCs of the library
  DO rust+INIT --keep_fingerprints=true

# prepare-cache:
#   FROM +deps
#   RUN cargo install --debug cargo-chef
#   COPY --dir server lib cli desktop Cargo.lock Cargo.toml .
#   RUN cargo chef prepare
#   SAVE ARTIFACT recipe.json

# build-server:
#   FROM +prepare-cache
#   WORKDIR /app
#   COPY +prepare-cache/recipe.json .
#   RUN cargo chef cook --release --recipe-path recipe.json --bin atomic-server --target x86_64-unknown-linux-musl
#   COPY browser+build/dist /app/browser/data-browser/dist
#   COPY --dir server lib cli desktop Cargo.lock Cargo.toml .
#   RUN cargo build --release --bin atomic-server --config net.git-fetch-with-cli=true --target x86_64-unknown-linux-musl
#   RUN strip -s /app/target/x86_64-unknown-linux-musl/release/atomic-server
#   SAVE ARTIFACT /app/target/x86_64-unknown-linux-musl/release/atomic-server /atomic-server

source:
  FROM +install
  COPY --keep-ts Cargo.toml Cargo.lock ./
  COPY --keep-ts --dir server lib cli desktop  ./
  COPY browser+build/dist /code/browser/data-browser/dist

# build builds with the Cargo release profile
build:
  FROM +source
  DO rust+CARGO --args="build --release" --output="release/[^/\.]+"
  SAVE ARTIFACT ./target/release/ target AS LOCAL artifact/target

# test executes all unit and integration tests via Cargo
test:
  FROM +source
  DO rust+CARGO --args="test"

# fmt checks whether Rust code is formatted according to style guidelines
fmt:
  FROM +source
  DO rust+CARGO --args="fmt --check"

# lint runs cargo clippy on the source code
lint:
  FROM +source
  DO rust+CARGO --args="clippy --no-deps --all-features --all-targets"

# test:
#   FROM +prepare-cache
#   WORKDIR /app
#   COPY +prepare-cache/recipe.json .
#   COPY browser+build/data-browser/dist /app/browser/data-browser/dist
#   RUN cargo chef cook --recipe-path recipe.json --bin atomic-server --target x86_64-unknown-linux-musl
#   COPY --dir server lib cli desktop Cargo.lock Cargo.toml .
#   RUN cargo test

# clippy:
#   FROM +build-server
#   RUN cargo clippy --no-deps

docker:
  COPY --chmod=0755 +build/target/atomic-server /atomic-server-bin
  # For a complete list of possible ENV vars or available flags, run with `--help`
  ENV ATOMIC_STORE_PATH="/atomic-storage/db"
  ENV ATOMIC_CONFIG_PATH="/atomic-storage/config.toml"
  ENV ATOMIC_PORT="80"
  EXPOSE 80
  VOLUME /atomic-storage
  ENTRYPOINT ["/atomic-server-bin"]
  # Push to github container registry
  # SAVE IMAGE --push ghcr.io/atomicdata-dev/atomic-server:latest
  # Push to dockerhub
  SAVE IMAGE --push joepmeneer/atomic-server:latest

setup-playwright:
  FROM mcr.microsoft.com/playwright:v1.38.0-jammy
  RUN curl -f https://get.pnpm.io/v6.14.js | node - add --global pnpm
  RUN apt update && apt install -y zip
  RUN pnpx playwright install --with-deps
  COPY browser/ /app
  WORKDIR app
  ENV FRONTEND_URL="http://localhost"
  ENV LANGUAGE="en_GB"
  RUN pnpm install
  RUN pnpm playwright-install
  ENV DELETE_PREVIOUS_TEST_DRIVES="false"

e2e:
  FROM +setup-playwright
  COPY --chmod=0755 +build/target/atomic-server /atomic-server-bin
  RUN nohup /atomic-server-bin --initialize &
  # We'll have to zip it https://github.com/earthly/earthly/issues/2817
  TRY
    RUN pnpm run test-e2e ; zip -r test.zip /app/data-browser/test-results
  FINALLY
    SAVE ARTIFACT test.zip AS LOCAL artifact/test-results.zip
  END


  # USE DOCKER
  # TRY
  #   WITH DOCKER \
  #     --load test:latest=+docker
  #     RUN docker run -d -p 80:80 test:latest  & \
  #     pnpm run test-e2e
  #   END
  #   FINALLY
  #     SAVE ARTIFACT /app/data-browser/test-results AS LOCAL artifact/test-results
  #   END
