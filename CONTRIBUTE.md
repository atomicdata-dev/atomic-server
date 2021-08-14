# Contribute

I'm glad you're reading this!
If you encounter issues, add them to the Github issue tracker.
Same goes for feature requests.
PR's are welcome, too!
And join our [Discord](https://discord.gg/a72Rv2P)!
I'd love to help you out to understand this codebase.

If you want to share some thoughts on Atomic Data as a standard, please [drop an issue in the Atomic Data docs repo](https://github.com/ontola/atomic-data/issues).

## Local development

Clone the repo and run `cargo run` from each folder (e.g. `cli` or `server`).
If you _also_ want to work on [the front-end](https://github.com/joepio/atomic-data-browser), run it with `SNOWPACK_PUBLIC_BASE_URL` set to your `atomic-server` (by default `localhost`).

## Making a perfect pull-request

- Clear explanation in the PR itself of what is changed and why
- Reference to relevant issues in commit messages (e.g. `#123 my commit message`)
- Tests are passing `cargo test --all`
- Linters are happy `cargo fmt` & `cargo clippy`

# Versioning and Tagging

- We use [semver](https://semver.org/), and are still quite far from 1.0.0.
- The version for `atomic-lib` is the most important, and dictates the versions of `cli` and `server`. When `lib` changes minor version, `cli` and `server` should follow.
- On pushing a version `v*` tag, a Release will automatically be created on Github with the binaries. This will read `CHANGELOG.md`, so make sure to add the changes from there. So tag the releases!
- Use `cargo workspaces version patch` (and maybe replace `patch` with the `minor`) to update the `cargo.toml` files in one command. You'll need to `cargo install cargo-workspaces`.

## Building and publishing binaries

1. `cargo build --release`
1. `cargo build --release --features desktop` if you want the tray item (mac + win support)
1. Create a release on github, add the binaries.

I've got to automate this process some day...

## Publishing to Cargo

1. Update the versions in cargo.toml files using Semantic Versioning.
1. run `cargo publish` in `lib`, than you can run the same in `cli` and `server`

OR

1. Install `cargo install cargo-release` and run `cargo release patch`

## Publishing server to Docker

DockerHub has been setup to track the `master` branch, but it does not tag builds other than `latest`.

1. build: `docker build . -t joepmeneer/atomic-server:v0.20.4 -t joepmeneer/atomic-server:latest`
1. publish: `docker push -a joepmeneer/atomic-server`

or:

1. build and publish various builds (warning: building to ARM takes long!): `docker buildx build --platform linux/amd64,linux/arm64 . -t joepmeneer/atomic-server:v0.20.4 -t joepmeneer/atomic-server:latest --push`. Note that including the armv7 platform `linux/arm/v7` currently fails.

## Deploy to atomicdata.dev

1. `cd server`
1. `cargo build --release --target x86_64-unknown-linux-gnu`
1. `scp ../target/x86_64-unknown-linux-gnu/release/atomic-server atomic:~/atomic/server/atomic-server-v0.23.0`
1. `ssh atomic` (@joepio manages server)
1. `htop` and kill `atomic`
1. `cd atomic/server`
1. `git pull` (if relevant static files have changed)
1. `rm -rf  ~/.config/atomic/db` (if the db is corrupted / migrated)
1. `./atomic-server-v0.23.0 &> log-v0.23.0-1` to start and log to file

## Publishing atomic-cli to WAPM

1. Install `wasmer` and `cargo-wasi`.
1. `cd cli`
1. run `cargo wasi build --release --no-default-features` (note: this fails, as ring does not compile to WASI [at this moment](https://github.com/briansmith/ring/issues/1043))
1. `wapm publish`
