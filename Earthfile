VERSION --try --global-cache 0.8
PROJECT ontola/atomic-server
IMPORT ./browser AS browser
IMPORT github.com/earthly/lib/rust AS rust
FROM rust:buster
WORKDIR /code

pipeline:
  BUILD browser+test
  BUILD browser+lint
  BUILD +fmt
  BUILD +docs-pages
  BUILD +lint
  BUILD +test
  BUILD +build
  BUILD +e2e

# Creates a `./artifact/bin` folder with all the atomic-server binaries
build-all:
  BUILD +build # x86_64-unknown-linux-gnu
  BUILD +cross-build --TARGET=x86_64-unknown-linux-musl
  BUILD +cross-build --TARGET=armv7-unknown-linux-musleabihf
  # GLIBC issue, see #833
  # BUILD +cross-build --TARGET=aarch64-unknown-linux-musl
  # Errors
  # BUILD +cross-build --TARGET=aarch64-apple-darwin

docker-all:
  BUILD --platform=linux/amd64 +docker-musl --TARGET=x86_64-unknown-linux-musl
  BUILD --platform=linux/arm/v7 +docker-musl --TARGET=armv7-unknown-linux-musleabihf
  # GLIBC issue, see #833
  # BUILD --platform=linux/arm64/v8 +docker-musl --TARGET=aarch64-unknown-linux-musl

install:
  RUN apt-get update -qq
  RUN rustup component add clippy
  RUN rustup component add rustfmt
  RUN cargo install cross
  DO rust+INIT --keep_fingerprints=true

source:
  FROM +install
  COPY --keep-ts Cargo.toml Cargo.lock ./
  COPY --keep-ts --dir server lib cli  ./
  COPY browser+build/dist /code/server/assets_tmp
  DO rust+CARGO --args=fetch

fmt:
  FROM +source
  DO rust+CARGO --args="fmt --check"

lint:
  FROM +source
  DO rust+CARGO --args="clippy --no-deps --all-features --all-targets"

build:
  FROM +source
  DO rust+CARGO --args="build --offline --release" --output="release/[^/\.]+"
  RUN ./target/release/atomic-server --version
  SAVE ARTIFACT ./target/release/atomic-server AS LOCAL artifact/bin/atomic-server-x86_64-unknown-linux-gnu

test:
  FROM +build
  DO rust+CARGO --args="test"

cross-build:
  FROM +source
  ARG --required TARGET
  DO rust+SET_CACHE_MOUNTS_ENV
  DO rust+CROSS --target ${TARGET}
  # DO rust+COPY_OUTPUT --output="release/[^\./]+"
  DO rust+COPY_OUTPUT --output=".*" # Copies all files to ./target
  RUN ./target/$TARGET/release/atomic-server --version
  SAVE ARTIFACT ./target/$TARGET/release/atomic-server AS LOCAL artifact/bin/atomic-server-$TARGET

docker-musl:
  FROM alpine:3.18
  # You can pass multiple tags, space separated
  ARG tags="joepmeneer/atomic-server:develop"
  ARG --required TARGET
  COPY --chmod=0755 --platform=linux/amd64 (+cross-build/atomic-server --TARGET=${TARGET}) /atomic-server-bin
  RUN /atomic-server-bin --version
  # For a complete list of possible ENV vars or available flags, run with `--help`
  ENV ATOMIC_DATA_DIR="/atomic-storage/data"
  ENV ATOMIC_CONFIG_DIR="/atomic-storage/config"
  ENV ATOMIC_PORT="80"
  EXPOSE 80
  VOLUME /atomic-storage
  ENTRYPOINT ["/atomic-server-bin"]
  RUN echo "Pushing tags: ${tags}"
  SAVE IMAGE --push ${tags}

setup-playwright:
  FROM mcr.microsoft.com/playwright:v1.38.0-jammy
  RUN curl -f https://get.pnpm.io/v6.14.js | node - add --global pnpm
  RUN apt update && apt install -y zip
  RUN pnpx playwright install --with-deps
  RUN npm install -g netlify-cli

e2e:
  FROM +setup-playwright
  COPY --keep-ts browser/e2e/package.json /app/e2e/package.json
  WORKDIR /app/e2e
  RUN pnpm install
  COPY --keep-ts --dir browser/e2e /app
  RUN pnpm install
  ENV LANGUAGE="en_GB"
  ENV DELETE_PREVIOUS_TEST_DRIVES="false"
  ENV FRONTEND_URL=http://localhost:9883
  COPY --chmod=0755 +build/atomic-server /atomic-server-bin
  # We'll have to zip it https://github.com/earthly/earthly/issues/2817
  TRY
    RUN nohup /atomic-server-bin --initialize & pnpm run test-e2e ; zip -r test.zip /app/e2e/playwright-report
  FINALLY
    SAVE ARTIFACT test.zip AS LOCAL artifact/test-results.zip
  END
  RUN unzip -o test.zip -d /artifact
  # upload to https://atomic-tests.netlify.app/
  RUN --secret NETLIFY_AUTH_TOKEN=NETLIFY_TOKEN netlify deploy --dir /artifact/app/e2e/playwright-report --prod --auth $NETLIFY_AUTH_TOKEN --site atomic-tests

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

docs-pages:
  RUN cargo install mdbook
  RUN cargo install mdbook-linkcheck
  RUN cargo install mdbook-sitemap-generator
  RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.5/install.sh | bash
  RUN bash -c "source $HOME/.nvm/nvm.sh && nvm install 20 && npm install -g netlify-cli"
  COPY --keep-ts docs /docs
  WORKDIR /docs
  RUN mdbook --version
  RUN mdbook build
  RUN mdbook-sitemap-generator -d docs.atomicdata.dev -o /docs/book/html/sitemap.xml
  RUN --secret NETLIFY_AUTH_TOKEN=NETLIFY_TOKEN bash -c "source $HOME/.nvm/nvm.sh && netlify deploy --dir /docs/book/html --prod --auth $NETLIFY_AUTH_TOKEN --site atomic-docs"
