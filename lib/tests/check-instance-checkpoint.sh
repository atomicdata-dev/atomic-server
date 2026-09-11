#!/bin/sh
# Run from the workspace root; select only atomic_lib to avoid feature unification.
set -eu
checkpoint_deps=$(mktemp)
trap 'rm -f "$checkpoint_deps"' EXIT HUP INT TERM
cargo tree --locked -p atomic_lib --no-default-features --features backup,config \
  --edges normal --prefix none --format '{p}' > "$checkpoint_deps"
if grep -E '^(atomic-server|actix(-[^ ]+)?) ' "$checkpoint_deps"; then
  echo 'Native checkpoints must not depend on atomic-server or Actix.' >&2
  exit 1
fi
cargo test --locked -p atomic_lib --no-default-features --features backup,config --test instance_checkpoint
cargo test --locked -p atomic_lib --no-default-features --features backup,config --lib backup::
