#!/bin/sh
# Install the same version as workspace.metadata.bin in Cargo.toml. Keep the
# binary in the container layer, not a mutable cache mount: a cached install
# must still contain its executable after Dagger evicts cache volumes.
set -eu

version=0.15.0
case "$(uname -m)" in
  x86_64)
    target=x86_64-unknown-linux-musl
    checksum=c09f971ecaed9a2efc80fdcea7a00ef6b53c7fadc8c57d1f61b53a6aa66b668a
    ;;
  aarch64)
    target=aarch64-unknown-linux-musl
    checksum=e17ef0806381c3a0acb9c9ddad643a49facaa5a2ecf657a421d4d8f3357a24b7
    ;;
  *) echo "Unsupported wasm-pack build architecture: $(uname -m)" >&2; exit 1 ;;
esac

archive="wasm-pack-v${version}-${target}"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT HUP INT TERM
curl --fail --location --silent --show-error --retry 3 \
  "https://github.com/wasm-bindgen/wasm-pack/releases/download/v${version}/${archive}.tar.gz" \
  --output "$scratch/wasm-pack.tar.gz"
printf '%s  %s\n' "$checksum" "$scratch/wasm-pack.tar.gz" | sha256sum --check
tar -xzf "$scratch/wasm-pack.tar.gz" -C "$scratch"
install -d "${1:-/usr/local/bin}"
install -m 755 "$scratch/$archive/wasm-pack" "${1:-/usr/local/bin}/wasm-pack"
"${1:-/usr/local/bin}/wasm-pack" --version
