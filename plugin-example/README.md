# Atomic Data Plugin Example

A minimal example of an Atomic Plugin, written in Rust, compiled to WASM.

## How Atomic Plugins work

Atomic Plugins are WASM (WebAssembly) applications that are executed in a Sandbox in an Atomic Server.
This makes them safe, performant, and very easy to install - no need to reboot the Server.
Check this issue: https://github.com/joepio/atomic/issues/73.

## How to run

```bash
# Compile to WASM
cargo build --target wasm32-unknown-unknown --release
# Run it using Wasmer, see https://wasmer.io/
wasmer ./target/wasm32-unknown-unknown/release/atomic_plugin_example.wasm -i fibonacci 20
# Or start a server and open it on http://localhost/show?subject=http%3A%2F%2Flocalhost%2Fwasm
```

Inspired by https://codeburst.io/webassembly-and-rust-there-and-back-again-9ad76f61d616
