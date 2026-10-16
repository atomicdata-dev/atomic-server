#!/usr/bin/env bash
# Rebuilds testdata/host-abi/ from the example apps on the host ABI.
#
# The server's host-abi tests load these prebuilt components rather than
# compiling wasm during `cargo test`. Run this after changing
# plugin-examples/host-abi-*, or atomic-host/wit, and commit the result.
set -euo pipefail

cd "$(dirname "$0")/.."

cargo build --target wasm32-wasip2 --release -p host-abi-counter -p host-abi-caller -p host-abi-module

out=testdata/host-abi
mkdir -p "$out"
cp target/wasm32-wasip2/release/host_abi_counter.wasm "$out/counter.wasm"
cp target/wasm32-wasip2/release/host_abi_caller.wasm "$out/caller.wasm"
cp target/wasm32-wasip2/release/host_abi_module.wasm "$out/module.wasm"
cp plugin-examples/host-abi-counter/manifest.json "$out/counter.manifest.json"
cp plugin-examples/host-abi-caller/manifest.json "$out/caller.manifest.json"
