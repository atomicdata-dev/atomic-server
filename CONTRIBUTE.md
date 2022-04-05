# Guide for Atomic Data Rust contributors

First things first: I'm glad you're reading this!
If you encounter any issues, add them to the [Github issue tracker](https://github.com/joepio/atomic-data-rust/issues).
Same goes for feature requests.
PR's are welcome, too!
And join our [Discord](https://discord.gg/a72Rv2P)!
I'd love to help you out to understand this codebase.
If you want to share some thoughts on the Atomic Data _specification_, please [drop an issue in the Atomic Data docs repo](https://github.com/ontola/atomic-data/issues).

## Table of contents

- [Table of contents](#table-of-contents)
- [Running locally](#running-locally)
- [Testing](#testing)
- [Code coverage](#code-coverage)
- [Debugging](#debugging)
- [Performance monitoring](#performance-monitoring)
  - [Tracing](#tracing)
  - [Criterion benchmarks](#criterion-benchmarks)
  - [Drill](#drill)
- [Releases, Versioning and Tagging](#releases-versioning-and-tagging)
- [Including JS app_assets](#including-js-app_assets)
- [Publishing manually - doing the CI's work](#publishing-manually---doing-the-cis-work)
  - [Building and publishing binaries](#building-and-publishing-binaries)
  - [Publishing to Cargo](#publishing-to-cargo)
  - [Publishing server to Docker](#publishing-server-to-docker)
  - [Deploying to atomicdata.dev](#deploying-to-atomicdatadev)
- [Publishing atomic-cli to WAPM](#publishing-atomic-cli-to-wapm)

## Running locally

Clone the repo and run `cargo run` from each folder (e.g. `cli` or `server`).

Since `atomic-server` is developed in conjunction with the typescript / react `atomic-data-browser` project, it might make sense to run both locally whilst developing.

- Clone [`atomic-data-browser`](https://github.com/joepio/atomic-data-browser) and run it (see readme.md, basically: `yarn start`)
- Visit `https://localhost:8080` (default)
- Visit your `localhost` in your locally running `atomic-data-browser` instance: (e.g. `http://localhost:8080/app/show?subject=http%3A%2F%2Flocalhost`)

## Testing

- All tests are run in CI

```sh
# Make sure nextest is installed
cargo install nextest
# This also makes sure that cli and server work, plus it test the db feature
cargo nextest run
# Run specific test(s)
cargo nextest run test_name_substring
# End-to-end tests, powered by PlayWright and Atomic-Data-Browser
# First, run the server
cargo run
# now, open new terminal window
cd server/e2e_tests/ && npm i && npm run test
# if things go wrong, debug!
npm run test-query {testname}
```

## Code coverage

- Visible at https://app.codecov.io/gh/joepio/atomic-data-rust/
- Checked in CI

```sh
# install cargo-llvm-cov, see https://github.com/taiki-e/cargo-llvm-cov
# Run the tests with a coverage report
cargo llvm-cov --all-features --show-missing-lines
```

## Debugging

- **VSCode Users**: Install the `CodeLLDB` plugin, and press F5 to start debugging. Breakpoints, inspect... The good stuff.

## Performance monitoring

We want to make Atomic Server as fast as possible.
For doing this, we have at least three tools: tracing, criterion and drill.

### Tracing

- Use the `tracing::instrument` macro to make functions traceable. Check out the [tracing](https://docs.rs/tracing/latest/tracing/) docs for more info.
- Run the server with the `--trace-chrome` flag.
- Close the server. A `trace-{unix-timestamp}.json` file will be generated in the current directory.
- Open this file with https://ui.perfetto.dev/ or `chrome://tracing`. This will show you a flamegraph that you can zoom into.

```sh
atomic-server --trace-chrome
```

### Criterion benchmarks

We have benchmarks in the `/lib/benchmarks` folder. Make sure there's a benchmark for the thing you're trying to optimize, run the benchmark, then make some changes to the code, then run the benchmark again. You should be able to see the difference in performance.

```sh
# install
cargo install cargo-criterion
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

## Releases, Versioning and Tagging

- We use Github Actions for building, testing and creating releases.
- Use `cargo workspaces version patch --force *` (and maybe replace `patch` with the `minor`) to update all `cargo.toml` files in one command. You'll need to `cargo install cargo-workspaces` if this command is not possible.
- Update the `tauri.conf.json` manually
- Push the `v*` tag, a Release will automatically be created on Github with the binaries. This will read `CHANGELOG.md`, so make sure to add the changes from there.
- The main action required on this repo, is to _update the changelog_ and _tag releases_. The tags trigger the build and publish processes in the CI.
- We use [semver](https://semver.org/), and are still quite far from 1.0.0.
- The version for `atomic-lib` is the most important, and dictates the versions of `cli` and `server`. When `lib` changes minor version, `cli` and `server` should follow.
- After publishing, update the `./desktop/latest-version.json` file. This is used for auto-updating desktop distributions. See [tauri docs](https://tauri.studio/docs/distribution/updater).

## Including JS app_assets

Before tagging a new version, make sure to update the `app_assets` folder:

1. get [atomic-data-browser](https://github.com/joepio/atomic-data-browser) locally
2. run `yarn build`
3. copy the contents of `publish` to `app_assets`
4. search and replace `./workbox` with `./app_assets/workbox` in `sw.js`, because we'll host `sw.js` from root.

## Publishing manually - doing the CI's work

If the CI scripts for some reason do not do their job (buildin releases, docker file, publishing to cargo), you can follow these instructions:

### Building and publishing binaries

1. `cargo build --release`
2. `cargo tauri build` (on every OS!)
3. Create a release on github, add the binaries and tauri builds

### Publishing to Cargo

1. Update the versions in cargo.toml files using Semantic Versioning.
1. run `cargo publish` in `lib`, than you can run the same in `cli` and `server`

OR

1. Install `cargo install cargo-release` and run `cargo release patch`

### Publishing server to Docker

DockerHub has been setup to track the `master` branch, but it does not tag builds other than `latest`.

1. build: `docker build . -t joepmeneer/atomic-server:v0.20.4 -t joepmeneer/atomic-server:latest`
1. run, make sure it works: `docker run joepmeneer/atomic-server:latest`
1. publish: `docker push -a joepmeneer/atomic-server`

or:

1. build and publish various builds (warning: building to ARM takes long!): `docker buildx build --platform linux/amd64,linux/arm64 . -t joepmeneer/atomic-server:v0.20.4 -t joepmeneer/atomic-server:latest --push`. Note that including the armv7 platform `linux/arm/v7` currently fails.

### Deploying to atomicdata.dev

1. Run the [`deploy` Github action](https://github.com/joepio/atomic-data-rust/actions/workflows/deployment.yml)

or do it manually:

1. `cd server`
1. `cargo build --release --target x86_64-unknown-linux-gnu`
1. `scp ../target/x86_64-unknown-linux-gnu/release/atomic-server atomic:~/atomic/server/atomic-server-v0.{version}`
1. `ssh atomic` (@joepio manages server)
2. `service atomic restart`

```sh
# logs
journalctl -u atomic.service
# logs, since one hour, follow
journalctl -u atomic.service --since "1 hour ago" -f
```

## Publishing atomic-cli to WAPM

1. Install `wasmer` and `cargo-wasi`.
1. `cd cli`
1. run `cargo wasi build --release --no-default-features` (note: this fails, as ring does not compile to WASI [at this moment](https://github.com/briansmith/ring/issues/1043))
1. `wapm publish`
