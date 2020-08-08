# Atomic

_Disclaimer: this project primarily serves as a project for me to learn Rust, and to check whether
the [Atomic Data spec](https://docs.atomicdata.dev) I'm working on actually makes some sense._

_Status: buggy, pre-alpha_

Create, share, fetch and model linked [Atomic Data](https://docs.atomicdata.dev)!
This project consists of a [CLI](#atomic-cli), a [server](#atomic-server) and a [library](#atomic-lib) for Rust.

## Install

### Using binaries

You can find the binaries on the [Releases page](https://github.com/joepio/atomic/releases/tag/v0.3.1).
Currently only builds for debian / ubuntu.

### From source

Install [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) to build from source.

```sh
git clone git@github.com:joepio/atomic.git
cd atomic
# Install atomic and atomic-server to path
cargo install --path ./
```

## Development

```sh
# You can pass arguments to binaries using cargo run like this
$ cargo run --bin atomic -- get class
```
