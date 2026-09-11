#!/usr/bin/env bash
#
# The two extra services a Cloud Vault e2e needs, on top of the ones
# `e2e-server.sh` and the vite dev server already provide.
#
#   MinIO           object storage the browser PUTs sealed packs to
#   atomic-saas     the control plane that brokers presigned URLs
#
# The vault path is the only part of the app that talks to a second backend, so
# it is the only suite that needs this. Everything else stays untouched.
#
#   ./scripts/vault-stack.sh          # start both, wait until healthy
#   ./scripts/vault-stack.sh --stop   # tear both down
#
# Ports are deliberately away from the defaults: 9100 for MinIO because 9000 is
# a popular default and another project's MinIO answering there produces
# `InvalidAccessKeyId`, which reads as a signing bug rather than "wrong server".
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SAAS_DIR="${ATOMIC_SAAS_DIR:-$REPO_ROOT/../atomic-saas}"
MINIO_PORT="${ATOMIC_VAULT_TEST_MINIO_PORT:-9100}"
# 3030, because that is hardcoded in atomic-saas's `main.rs` — there is no port
# env var. Inventing one here meant the control plane started fine on 3030
# while this script polled 3031 and reported it dead.
SAAS_PORT=3030
BUCKET=atomic-vault-e2e
MINIO_DATA="${ATOMIC_VAULT_E2E_MINIO_DATA:-/tmp/atomic-vault-e2e}"
SAAS_DB="${ATOMIC_SAAS_E2E_DB:-/tmp/atomic-vault-e2e-saas.redb}"
SAAS_LOG="${ATOMIC_SAAS_E2E_LOG:-/tmp/atomic-vault-e2e-saas.log}"
PID_FILE=/tmp/atomic-vault-e2e-saas.pid

# The node the control plane hands every enrolled drive to. It MUST be the
# server the SPA itself talks to (`data-browser/.env.development`, 9885 when
# the control plane is in play) — the app reconciles a drive's server URL to
# its enrollment's `http_origin`, so a mismatch silently repoints the drive at
# a port nothing is listening on. That surfaces as endless
# `ws://localhost:9883 connection refused` and commits that never land, which
# reads like a sync bug rather than a fixture one.
#
# atomic-saas defaults this to 9883 (`config.rs`), which is the standalone-
# server port, so it has to be set explicitly here.
# Same precedence vite applies: `.env.development.local` wins over the
# committed default. Read one file at a time — grep over several prefixes each
# line with its filename, which silently produces a garbage origin.
read_spa_server_url() {
  local url='' file found
  for file in \
    "$REPO_ROOT/browser/data-browser/.env.development" \
    "$REPO_ROOT/browser/data-browser/.env.development.local"; do
    [[ -f "$file" ]] || continue
    found=$(grep -E '^\s*VITE_ATOMIC_SERVER_URL=' "$file" | tail -1 |
      cut -d= -f2- | tr -d '"' | tr -d "'" | xargs || true)
    [[ -n "$found" ]] && url="$found"
  done
  echo "${url#*://}"
}

DEV_NODE_ORIGIN="${ATOMIC_VAULT_E2E_NODE_ORIGIN:-$(read_spa_server_url)}"
DEV_NODE_ORIGIN="${DEV_NODE_ORIGIN:-localhost:9885}"

stop() {
  docker rm -f atomic-vault-e2e-minio >/dev/null 2>&1 || true

  if [[ -f "$PID_FILE" ]]; then
    kill "$(cat "$PID_FILE")" 2>/dev/null || true
    rm -f "$PID_FILE"
  fi

  echo "vault stack stopped"
}

if [[ "${1:-}" == "--stop" ]]; then
  stop
  exit 0
fi

stop

# ── MinIO ──────────────────────────────────────────────────────────────────
# The bucket is just a directory: MinIO's filesystem backend exposes each
# top-level directory under its data path as one, so no mc/aws CLI is needed.
# Clear the bucket's contents, not the mount root. Deleting and recreating the
# directory Docker is bind-mounting leaves the daemon looking at the old inode,
# and MinIO fails with "Unable to use the drive /data: drive not found".
mkdir -p "$MINIO_DATA/$BUCKET"
rm -rf "${MINIO_DATA:?}/$BUCKET"/*

docker run -d --name atomic-vault-e2e-minio \
  -p "$MINIO_PORT:9000" \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=minioadmin \
  -e MINIO_DOMAIN=localhost \
  -v "$MINIO_DATA:/data" \
  minio/minio server /data >/dev/null

for _ in $(seq 1 30); do
  curl -sf "http://localhost:$MINIO_PORT/minio/health/live" >/dev/null && break
  sleep 1
done

# `docker run` fails *silently* on a port clash when its output is redirected,
# leaving a container in `Created` while the health check above passes against
# whatever already owns the port. Check the container, not just the health.
if [[ -z "$(docker ps --filter name=atomic-vault-e2e-minio --format '{{.ID}}')" ]]; then
  echo "MinIO did not start — is something already on port $MINIO_PORT?" >&2
  docker logs atomic-vault-e2e-minio 2>&1 | tail -20 >&2
  exit 1
fi

echo "MinIO up on $MINIO_PORT (bucket $BUCKET)"

# ── Control plane ──────────────────────────────────────────────────────────
if [[ ! -d "$SAAS_DIR" ]]; then
  echo "atomic-saas checkout not found at $SAAS_DIR — set ATOMIC_SAAS_DIR." >&2
  exit 1
fi

rm -f "$SAAS_DB"

# Build the portal here rather than borrowing one from another checkout.
#
# The control plane embeds `portal/dist` at compile time, so a missing dist
# fails the build and it is tempting to copy one across. Do not: a production
# build has `VITE_ATOMIC_APP_URL` baked in, which overrides the portal's own
# runtime "am I on localhost" check and sends a local sign-in to
# app.atomicserver.eu. Built here with that variable unset, the fallback
# applies and sign-in lands on the local app.
#
# Must happen before `cargo run`, since the assets are compiled in.
if [[ ! -f "$SAAS_DIR/portal/dist/index.html" ]] || \
   [[ ! -f "$SAAS_DIR/portal/.env.production.local" ]] || \
   grep -rqs "app.atomicserver.eu" "$SAAS_DIR/portal/dist/assets"; then
  # The portal links to @tomic/lib and @tomic/edit-mode by `file:` path into
  # the sibling atomic-server checkout, so those have to be built first. A
  # fresh worktree has no build outputs and the failure surfaces as
  # "Cannot find module '@tomic/lib'", which names the symptom rather than
  # the cause.
  # Resolved from the portal's own `file:` paths, which point at whatever
  # atomic-server sits beside *the control plane checkout* — not necessarily
  # this one. Getting that wrong reports a directory that is already built
  # while the build keeps failing.
  portal_sibling="$(cd "$SAAS_DIR/../atomic-server" 2>/dev/null && pwd || true)"

  if [[ -z "$portal_sibling" ]]; then
    echo "No atomic-server beside $SAAS_DIR — the portal links to it by file: path." >&2
    exit 1
  fi

  for pkg in lib edit-mode; do
    if [[ ! -f "$portal_sibling/browser/$pkg/dist/index.js" ]]; then
      echo "The portal needs @tomic/$pkg built in the checkout it links to:" >&2
      echo "  cd $portal_sibling/browser && pnpm install && pnpm --filter @tomic/$pkg build" >&2
      exit 1
    fi
  done

  echo "building the portal for local use..."
  (
    cd "$SAAS_DIR/portal"
    [[ -d node_modules ]] || npm ci --silent
    # `npm run build` runs vite in production mode, which loads
    # `portal/.env.production` from disk — and that file hardcodes
    # VITE_ATOMIC_APP_URL=https://app.atomicserver.eu. Unsetting the process
    # variable does nothing about a file. `.env.production.local` takes
    # precedence over it and is gitignored, so the committed default stays
    # correct for real deploys while a local build points at the local app.
    printf 'VITE_ATOMIC_APP_URL=http://localhost:6747\n' > .env.production.local
    npm run build --silent
  ) || { echo "portal build failed" >&2; exit 1; }
fi

# Virtual-hosted addressing puts the bucket in the host name. macOS resolves
# *.localhost natively; Linux does not, so name it once.
if ! grep -q "$BUCKET.localhost" /etc/hosts 2>/dev/null; then
  if [[ "$(uname)" != "Darwin" ]]; then
    echo "127.0.0.1 $BUCKET.localhost" | sudo tee -a /etc/hosts >/dev/null
  fi
fi

# `nohup` and no subshell: a backgrounded job inside `( ... )` dies with the
# subshell, which showed up as an empty log and no process rather than an
# error. This keeps the control plane alive after the script returns.
(
  cd "$SAAS_DIR" || exit 1
  # Dev magic links so the suite can sign in without a mail server, and a
  # throwaway DB so a run never touches a real one.
  #
  # The local-process node provider is chosen only to avoid HCLOUD_TOKEN: the
  # Hetzner provider demands one at construction, and the vault needs no
  # managed nodes at all — it brokers presigned URLs, nothing more. No node is
  # ever spawned here.
  # `nohup` alone, no `setsid`: macOS has no setsid, and nohup plus the PID
  # check below is enough to both detach and notice a startup crash.
  nohup env \
    RUST_LOG=info,atomic_saas=debug \
    ATOMIC_SAAS_DEV_MAGIC_LINKS=true \
    POSTMARK_TOKEN=mock \
    POSTMARK_FROM=e2e@localhost \
    ATOMIC_SAAS_SKIP_NODE_HEALTH_CHECKS=true \
    ATOMIC_SAAS_NODE_PROVIDER=local-process \
    ATOMIC_SAAS_DEV_NODE_ORIGIN="$DEV_NODE_ORIGIN" \
    ATOMIC_SAAS_SIGNUP_PER_IP_CAP="${ATOMIC_SAAS_SIGNUP_PER_IP_CAP:-10000}" \
    ATOMIC_SAAS_SIGNUP_EMAIL_COOLDOWN_SECS="${ATOMIC_SAAS_SIGNUP_EMAIL_COOLDOWN_SECS:-0}" \
    DB_PATH="$SAAS_DB" \
    SAAS_URL="http://localhost:$SAAS_PORT" \
    ATOMIC_VAULT_S3_BUCKET="$BUCKET" \
    ATOMIC_VAULT_S3_REGION=us-east-1 \
    ATOMIC_VAULT_S3_ENDPOINT="http://$BUCKET.localhost:$MINIO_PORT" \
    ATOMIC_VAULT_S3_VIRTUAL_HOSTED=1 \
    ATOMIC_VAULT_S3_ALLOW_HTTP=1 \
    ATOMIC_VAULT_PSEUDONYM_SALT=e2e-salt \
    AWS_ACCESS_KEY_ID=minioadmin \
    AWS_SECRET_ACCESS_KEY=minioadmin \
    cargo run --quiet --bin atomic-saas >"$SAAS_LOG" 2>&1 &
  echo $! >"$PID_FILE"
) 
# First run compiles atomic-saas, which takes minutes rather than seconds.
#
# `set -e` and polling do not mix: a bare `curl ... && break` is a compound
# command whose failure aborts the whole script, so the first poll against a
# port nothing is listening on yet ends the run. Every probe is therefore
# guarded with `|| true`.
up=false

for _ in $(seq 1 300); do
  if ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "control plane exited during startup — see $SAAS_LOG" >&2
    tail -20 "$SAAS_LOG" >&2
    exit 1
  fi

  # Any HTTP answer means it is listening; /api/me is 401 without a session.
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$SAAS_PORT/api/me" || true)

  if [[ "$code" != "000" ]]; then
    up=true
    break
  fi

  sleep 1
done

if [[ "$up" != true ]]; then
  echo "control plane did not come up — see $SAAS_LOG" >&2
  tail -20 "$SAAS_LOG" >&2
  exit 1
fi

# Without a bucket the control plane falls back to an in-memory stub whose
# upload URLs are not real. A browser test would then pass while storing
# nothing, so confirm the real backend rather than trusting the env vars.
if grep -q "in-memory stub" "$SAAS_LOG"; then
  echo "control plane fell back to the in-memory vault stub — S3 config is wrong" >&2
  grep -i vault "$SAAS_LOG" >&2
  exit 1
fi

echo "control plane up on $SAAS_PORT (log: $SAAS_LOG)"

# The control plane is only half the stack. Every enrolled drive is assigned to
# the node above, and the SPA follows that assignment — so if nothing answers
# there, drives are created but commits never land and the failure surfaces
# somewhere far away ("waiting for response" in a title helper). Say so here
# instead, where it is one line to fix.
if ! curl -sf -o /dev/null -m 3 "http://$DEV_NODE_ORIGIN/" 2>/dev/null; then
  echo
  echo "WARNING: nothing is listening on $DEV_NODE_ORIGIN, the node this" >&2
  echo "control plane assigns every drive to. Drives will be created but" >&2
  echo "their commits will never land. Start it with:" >&2
  echo "  cd browser/e2e && ./scripts/e2e-server.sh" >&2
else
  echo "node up on $DEV_NODE_ORIGIN (drives are assigned here)"
fi

echo
echo "The SPA reaches the control plane at http://localhost:$SAAS_PORT"
echo "Start Vite with VITE_MANAGED_API_BASE=http://localhost:$SAAS_PORT/api to enable SaaS requests."
