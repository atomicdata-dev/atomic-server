# Atomic Data Plugin Example

A minimal example of an Atomic Plugin, written in Rust, compiled to WASM.

## How Atomic Plugins work

Atomic Plugins are WASM (WebAssembly) applications that are executed in a Sandbox in an Atomic Server.
This will make them safe, performant, and very easy to install.
It's currently a work-in-progress.
Powered by [`fp-bindgen`](https://github.com/fiberplane/fp-bindgen/).

Check this issue: https://github.com/joepio/atomic/issues/73.

## How to compile and run

```bash
# Compile to WASM
cargo build --target wasm32-unknown-unknown --release
# Move to this folder, overwrite existing file
mv ../../target/wasm32-unknown-unknown/release/plugin-example.wasm ./plugin_example.wasm
# Start the server!
cargo run --bin server
```
