# Contribute

I'm glad you're reading this!
If you encounter issues, add them to the Github issue tracker.
Same goes for feature requests.
PR's are welcome, too!
And join our [Discord](https://discord.gg/a72Rv2P)!

If you want to share some thoughts on Atomic Data as a standard, please [drop an issue in the Atomic Data docs repo](https://github.com/ontola/atomic-data/issues).

## Local development

Clone the repo and run `cargo run` from each folder (e.g. `cli` or `server`).
Make sure to `cargo test --all` before opening a PR!

## Publishing to Cargo

1. Update the versions in cargo.toml files using Semantic Versioning.
1. run `cargo publish` in `lib`, than you can run the same in `cli` and `server`

## Deploy

1. `cd server`
1. `cargo build --release --target x86_64-unknown-linux-gnu`
1. `scp ../target/x86_64-unknown-linux-gnu/release/atomic-server atomic:~/atomic/server/atomic-server-v0.20.0`
1. `ssh atomic`
1. `htop` and kill `atomic`
1. `cd atomic/server`
1. `git pull` (if relevant static files have changed)
1. `rm -rf  ~/.config/atomic/db` (if the db is corrupted / migrated)
1. `./atomic-server-v0.20.0 &> log-v0.20.0-1` to start and log to file

## Publishing to WAPM

1. run `cargo wasi build --release` (note: this fails, as ring does not compile to WASI [at this moment](https://github.com/briansmith/ring/issues/657))
1. `wapm publish`
