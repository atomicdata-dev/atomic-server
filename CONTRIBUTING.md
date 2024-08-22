# Guide for Atomic-Server contributors

First things first: I'm glad you're reading this!
Join our [Discord](https://discord.gg/a72Rv2P) to chat with other people in the Atomic Data community.
If you encounter any issues, add them to the [Github issue tracker](https://github.com/atomicdata-dev/atomic-server/issues).
Same goes for feature requests.
PR's are welcome, too!
Note that opening a PR means agreeing that your code becomes distributed under the MIT license.

If you want to share some thoughts on the Atomic Data _specification_, please [drop an issue in the Atomic Data docs repo](https://github.com/ontola/atomic-data/issues).
Check out the [Roadmap](https://docs.atomicdata.dev/roadmap.html) if you want to learn more about our plans and the history of the project.

## Table of contents

- [Table of contents](#table-of-contents)
- [Running \& compiling](#running--compiling)
  - [Running locally (with local development browser)](#running-locally-with-local-development-browser)
  - [IDE setup (VSCode)](#ide-setup-vscode)
  - [Compilation using Earthly](#compilation-using-earthly)
  - [Improve local compilation speed](#improve-local-compilation-speed)
  - [Cross compilation](#cross-compilation)
- [Git policy](#git-policy)
  - [Open a PR](#open-a-pr)
  - [Branching](#branching)
- [Testing](#testing)
- [Performance monitoring / benchmarks](#performance-monitoring--benchmarks)
  - [Tracing](#tracing)
    - [Tracing with OpenTelemetry (and Jaeger)](#tracing-with-opentelemetry-and-jaeger)
    - [Tracing with Chrome](#tracing-with-chrome)
  - [Criterion benchmarks](#criterion-benchmarks)
  - [Drill](#drill)
- [Responsible disclosure / Coordinated Vulnerability Disclosure](#responsible-disclosure--coordinated-vulnerability-disclosure)
- [Releases, Versioning and Tagging](#releases-versioning-and-tagging)
  - [CI situation](#ci-situation)
  - [Publishing manually - doing the CI's work](#publishing-manually---doing-the-cis-work)
    - [Building and publishing binaries](#building-and-publishing-binaries)
    - [Publishing to Cargo](#publishing-to-cargo)
    - [Publishing server to Docker](#publishing-server-to-docker)
    - [Deploying to atomicdata.dev](#deploying-to-atomicdatadev)
    - [Publishing atomic-cli to WAPM](#publishing-atomic-cli-to-wapm)

## Running & compiling

TL;DR Clone the repo and run `cargo run` from each folder (e.g. `cli` or `server`).

### Running locally (with local development browser)

- Run `cargo run` to start the server
- Go to `browser`, run `pnpm install` (if you haven't already), and run `pnpm dev` to start the browser
- Visit your `localhost` in your locally running `atomic-data-browser` instance: (e.g. `http://localhost:5173/app/show?subject=http%3A%2F%2Flocalhost`)
- use `cargo watch -- cargo run` to automatically recompile `atomic-server` when you update JS assets in `browser`
- use `cargo watch -- cargo run --bin atomic-server -- --env-file server/.env` to automatically recompile `atomic-server` when you update code or JS assets.

### IDE setup (VSCode)

This project is primarily being developed in VSCode.
That doesn't mean that you should, too, but it means you're less likely to run into issues.

- **Tasks**: The `/.vscode` directory contains various `tasks` (open command palette => search "run task")
- **Debugging**: Install the `CodeLLDB` plugin, and press F5 to start debugging. Breakpoints, inspect... The good stuff.
- **Extensions**: That same directory will give a couple of suggestions for extensions to install.

### Compilation using Earthly

There are `earthfile`s in `browser` and in `atomic-server`.
These can be used by Earthly to build all steps, including a full docker image.

- Make sure `earthly` is installed
- `earthly --org ontola -P --satellite henk --artifact +e2e/test-results +pipeline`
- `earthly --org ontola -P --satellite henk --artifact +build-server/atomic-server ./output/atomicserver`

### Improve local compilation speed

- Use the [`mold`](https://github.com/rui314/mold) linker + create a `.cargo/config.toml` and add `[build] rustflags = ["-C", "link-arg=-fuse-ld=lld"]`
- Note: this is primarily for development on linux systems, as mold for macOS requires a paid license

### Cross compilation

If you want to build `atomic-server` for some other target (e.g. building for linux from macOS), you can use the `cross` crate, which requires `docker`.

```sh
cargo install cross
# make sure docker is running!
cross build --target x86_64-unknown-linux-musl --bin atomic-server --release
```

Note that this is also done in the `earthly` file.

## Git policy

### Open a PR

- Make sure your branch is up to date with `develop`.
- Open a PR against `develop`.
- Make sure all relevant tests / lint pass.

### Branching

Create new branches off `develop`. When an issue is ready for PR, open PR against `develop`.

## Testing

```sh
# Make sure nextest is installed
cargo install cargo-nextest
# Runs all tests
# NOTE: run this from the root of the workspace, or else feature flags may be excluded
cargo nextest run
# Run specific test(s)
cargo nextest run test_name_substring
# End-to-end tests, powered by PlayWright and Atomic-Data-Browser
# First, run the server
cargo run
# now, open new terminal window
cd server/e2e_tests/ && npm i && npm run test
# if things go wrong, debug!
pnpm run test-query {testname}
```

<!--
NOTE: NOT WORKING SINCE EARHTLY

## Code coverage

- Visible at https://app.codecov.io/gh/atomicdata-dev/atomic-server/
- Checked in CI

```sh
# install cargo-llvm-cov, see https://github.com/taiki-e/cargo-llvm-cov
# Run the tests with a coverage report
cargo llvm-cov --all-features --show-missing-lines
``` -->

## Performance monitoring / benchmarks

We want to make Atomic Server as fast as possible.
For doing this, we have at least three tools: tracing, criterion and drill.

### Tracing

There are two ways you can use `tracing` to get insights into performance.

#### Tracing with OpenTelemetry (and Jaeger)

- Run the server with `--trace opentelemetry` and add `--log-level trace` to inspect more events
- Run an OpenTelemetry compatible service, such as [Jaeger](https://www.jaegertracing.io/docs/1.34/getting-started/). See `docker run` command below or use the vscode task.
- Visit jaeger: `http://localhost:16686`

```sh
docker run -d --platform linux/amd64 --name jaeger \
  -e COLLECTOR_ZIPKIN_HTTP_PORT=9411 \
  -p 5775:5775/udp \
  -p 6831:6831/udp \
  -p 6832:6832/udp \
  -p 5778:5778 \
  -p 16686:16686 \
  -p 14268:14268 \
  -p 9411:9411 \
  jaegertracing/all-in-one:1.6
```

#### Tracing with Chrome

- Use the `tracing::instrument` macro to make functions traceable. Check out the [tracing](https://docs.rs/tracing/latest/tracing/) docs for more info.
- Run the server with the `--trace chrome` flag.
- Close the server. A `trace-{unix-timestamp}.json` file will be generated in the current directory.
- Open this file with https://ui.perfetto.dev/ or `chrome://tracing`. This will show you a flamegraph that you can zoom into.

### Criterion benchmarks

We have benchmarks in the `/lib/benchmarks` folder. Make sure there's a benchmark for the thing you're trying to optimize, run the benchmark, then make some changes to the code, then run the benchmark again. You should be able to see the difference in performance.

```sh
# install criterion
cargo install cargo-criterion
# go to atomic-server root folder - don't run benchmarks in `./lib`
cd ..
# run benchmark
cargo criterion
# or if that does not work
cargo bench --all-features
```

### Drill

HTTP-level benchmarking tool.
Sends a ton of requests, measures how long it takes.

```sh
cargo install drill
drill -b benchmark.yml --stats
```

## Responsible disclosure / Coordinated Vulnerability Disclosure

If you encounter serious security risks, please refrain from posting these publicly in the issue tracker.
We could minimize the impact by first patching the issue, publishing the patch, and then (after 30 days) disclose the bug.
So please first send an e-mail to joep@ontola.io describing the issue, and then we will work on fixing it as soon as possible.

## Releases, Versioning and Tagging

1. Commit changes
1. Make sure all tests run properly
1. Test, build and update the `/browser` versions (`package.json` files, see `./browser/contributing.md`)
1. Use `cargo workspaces version patch --no-git-commit` (and maybe replace `patch` with the `minor`) to update all `cargo.toml` files in one command. You'll need to `cargo install cargo-workspaces` if this command is not possible.
1. Publish to cargo: `cargo publish`. First `lib`, then `cli` and `server`.
1. Publish to `npm` (see `browser/contribute.md`)
1. Update the `CHANGELOG.md` files (browser and root)

The following should be triggered automatically:

- Push the `v*` tag, a Release will automatically be created on Github with the binaries. This will read `CHANGELOG.md`, so make sure to add the changes from there.
- The main action required on this repo, is to _update the changelog_ and _tag releases_. The tags trigger the build and publish processes in the CI.

Note:

- We use [semver](https://semver.org/), and are still quite far from 1.0.0.
- The version for `atomic-lib` is the most important, and dictates the versions of `cli` and `server`. When `lib` changes minor version, `cli` and `server` should follow.

### CI situation

- Github Action for `push`: builds + tests + docker (using `earthly`, see `Earthfile`)
- Github Action for `tag`: create release + publish binaries

### Publishing manually - doing the CI's work

If the CI scripts for some reason do not do their job (buildin releases, docker file, publishing to cargo), you can follow these instructions:

#### Building and publishing binaries

1. `cargo build --release`
1. Create a release on github, add the binaries

#### Publishing to Cargo

1. Update the versions in cargo.toml files using Semantic Versioning.
1. run `cargo publish` in `lib`, than you can run the same in `cli` and `server`

OR

1. Install `cargo install cargo-release` and run `cargo release patch`

#### Publishing server to Docker

DockerHub has been setup to track the `master` branch, but it does not tag builds other than `latest`.

1. build: `docker build . -t joepmeneer/atomic-server:v0.20.4 -t joepmeneer/atomic-server:latest`
1. run, make sure it works: `docker run joepmeneer/atomic-server:latest`
1. publish: `docker push -a joepmeneer/atomic-server`

or:

1. build and publish various builds (warning: building to ARM takes long!): `docker buildx build --platform linux/amd64,linux/arm64 . -t joepmeneer/atomic-server:v0.20.4 -t joepmeneer/atomic-server:latest --push`. Note that including the armv7 platform `linux/arm/v7` currently fails.

#### Deploying to atomicdata.dev

1. Run the [`deploy` Github action](https://github.com/atomicdata-dev/atomic-server/actions/workflows/deployment.yml)

or do it manually:

1. `cd server`
1. `cargo build --release --target x86_64-unknown-linux-musl --bin atomic-server` (if it fails, use cross, see above)
1. `scp ../target/x86_64-unknown-linux-gnu/release/atomic-server atomic:~/atomic/server/atomic-server-v0.{version}`
1. `ssh atomic` (@joepio manages server)
1. `service atomic restart`

```sh
# logs
journalctl -u atomic.service
# logs, since one hour, follow
journalctl -u atomic.service --since "1 hour ago" -f
```

#### Publishing atomic-cli to WAPM

1. Install `wasmer` and `cargo-wasi`.
1. `cd cli`
1. run `cargo wasi build --release --no-default-features` (note: this fails, as ring does not compile to WASI [at this moment](https://github.com/briansmith/ring/issues/1043))
1. `wapm publish`
