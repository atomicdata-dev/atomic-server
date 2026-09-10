#!/bin/sh
# Run from the workspace root. Isolate core features from server feature unification.
set -eu
runtime_deps=$(mktemp)
trap 'rm -f "$runtime_deps"' EXIT HUP INT TERM
cargo tree --locked -p atomic_lib --no-default-features --features db-redb,config \
  --edges normal --prefix none --format '{p}' > "$runtime_deps"
if grep -E '^(atomic-server|actix(-[^ ]+)?) ' "$runtime_deps"; then
  echo 'Native runtime must not depend on atomic-server or Actix.' >&2
  exit 1
fi
cargo test --locked -p atomic_lib --no-default-features --features db-redb,config --test native_runtime
