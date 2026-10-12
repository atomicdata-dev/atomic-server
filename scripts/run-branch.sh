#!/usr/bin/env bash
#
# Run any branch of atomic-server (server + embedded frontend) so you can try
# it from another device, e.g. a tablet on the same network.
#
#   scripts/run-branch.sh <branch> [--port 9883] [--keep-data] [--no-run] [--tunnel]
#
# Why this exists instead of `git checkout && cargo run`:
#   - It uses a worktree, so it never touches your checkout (a running vite
#     rewrites the tracked `src/locales/*.po` files and blocks `git checkout`).
#   - It has its own CARGO_TARGET_DIR, so it never waits on the lock of a build
#     you already have running. Reused across branches, so only the first run
#     compiles the dependencies.
#   - It builds the frontend + WASM itself, BEFORE cargo, with a visible line
#     per phase. (Left to build.rs, that step is silent for minutes and looks
#     hung.) The frontend is skipped when its inputs are unchanged.
#   - It serves on 0.0.0.0 and prints the LAN URL. NOTE: the app needs a secure
#     origin (OPFS), so over plain http only http://localhost works; another
#     device on the LAN gets "could not open local storage". Use --tunnel for
#     those: it starts a cloudflared quick tunnel and serves under its https
#     URL (public while it runs; needs `cloudflared`; tunnelto breaks the
#     websocket, don't use it).
#
# Env: ATOMIC_BRANCH_HOME (default ~/.cache/atomic-branches) holds the worktrees,
# the shared target dir and per-branch data dirs.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOME_DIR="${ATOMIC_BRANCH_HOME:-$HOME/.cache/atomic-branches}"
PORT=9883
KEEP_DATA=0
NO_RUN=0
TUNNEL=0
BRANCH=""

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --keep-data) KEEP_DATA=1; shift ;;
    --no-run) NO_RUN=1; shift ;;
    --tunnel) TUNNEL=1; shift ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option $1" >&2; exit 2 ;;
    *) BRANCH="$1"; shift ;;
  esac
done
[ -n "$BRANCH" ] || { echo "usage: $0 <branch> [--port N] [--keep-data] [--no-run] [--tunnel]" >&2; exit 2; }

T0=$(date +%s)
phase() { printf '\033[36m[run-branch %4ss]\033[0m %s\n' "$(( $(date +%s) - T0 ))" "$*"; }
die() { printf '\033[31m[run-branch]\033[0m %s\n' "$*" >&2; exit 1; }

SAFE="$(printf '%s' "$BRANCH" | tr -c 'A-Za-z0-9._-' '_')"
WT="$HOME_DIR/worktrees/$SAFE"
DATA="$HOME_DIR/data/$SAFE"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME_DIR/target}"
# A global `build-dir` in ~/.cargo/config.toml is shared by every repo and
# worktree and carries its own lock: a running `cargo run` anywhere then blocks
# every other cargo (also the one inside wasm-pack), silently, at 0% CPU.
export CARGO_BUILD_BUILD_DIR="${CARGO_BUILD_BUILD_DIR:-$CARGO_TARGET_DIR/build}"
mkdir -p "$HOME_DIR/worktrees" "$DATA"

phase "fetching $BRANCH"
git -C "$REPO_ROOT" fetch origin "$BRANCH" 2>&1 | tail -n 2 || die "cannot fetch $BRANCH from origin"
SHA="$(git -C "$REPO_ROOT" rev-parse FETCH_HEAD)"

if [ -d "$WT" ]; then
  # Our own worktree: any local change in it is generated output, not work.
  git -C "$WT" checkout --quiet --detach --force "$SHA"
else
  git -C "$REPO_ROOT" worktree add --quiet --detach "$WT" "$SHA"
fi
phase "worktree $WT at ${SHA:0:9}"

# Frontend inputs: hash the git trees, so identical content is recognised across
# checkouts (mtimes change on every checkout and say nothing about content).
INPUTS="$(for p in browser wasm lib; do git -C "$WT" rev-parse "HEAD:$p"; done | tr '\n' '-')"
STAMP="$WT/browser/data-browser/dist/.run-branch-inputs"

if [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$INPUTS" ] && [ -f "$WT/browser/data-browser/public/wasm/atomic_wasm_bg.wasm" ]; then
  phase "frontend inputs unchanged, skipping frontend + WASM build"
else
  phase "pnpm install"
  (cd "$WT/browser" && pnpm install --frozen-lockfile --reporter=silent) || die "pnpm install failed"
  phase "building frontend + WASM (first time: several minutes, wasm-pack compiles Rust; log: $WT/frontend-build.log)"
  (cd "$WT/browser" && pnpm run -r build) >"$WT/frontend-build.log" 2>&1 &
  BP=$!
  while kill -0 "$BP" 2>/dev/null; do sleep 20; kill -0 "$BP" 2>/dev/null && phase "  ...still building frontend ($(tail -n 1 "$WT/frontend-build.log" | cut -c1-100))"; done
  wait "$BP" || { tail -n 40 "$WT/frontend-build.log"; die "frontend build failed"; }
  echo "$INPUTS" >"$STAMP"
fi

phase "cargo build (target dir $CARGO_TARGET_DIR; first time compiles all dependencies)"
(cd "$WT" && ATOMICSERVER_SKIP_JS_BUILD=true cargo build -p atomic-server --color always 2>&1 | grep -v '^warning: atomic-server@' ) || die "cargo build failed"
BIN="$CARGO_TARGET_DIR/debug/atomic-server"

[ "$NO_RUN" = 1 ] && { phase "built $BIN"; exit 0; }

[ "$KEEP_DATA" = 1 ] || rm -rf "$DATA" && mkdir -p "$DATA"
LAN_IP="$(ipconfig getifaddr en0 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || true)"
export ATOMIC_DATA_DIR="$DATA" ATOMIC_PORT="$PORT" ATOMIC_IP=0.0.0.0
URL="http://localhost:$PORT  (other devices: http://${LAN_IP:-<ip>}:$PORT, but local storage only works over https, see --tunnel)"
if [ "$TUNNEL" = 1 ]; then
  command -v cloudflared >/dev/null || die "--tunnel needs cloudflared (brew install cloudflared)"
  TLOG="$HOME_DIR/cloudflared-$SAFE.log"
  cloudflared tunnel --no-autoupdate --url "http://localhost:$PORT" >"$TLOG" 2>&1 &
  TP=$!
  trap 'kill $TP ${SP:-} 2>/dev/null || true' EXIT INT TERM
  THOST=""
  for _ in $(seq 1 30); do
    THOST="$(grep -oE '[a-z0-9-]+\.trycloudflare\.com' "$TLOG" | head -n 1 || true)"
    [ -n "$THOST" ] && break
    sleep 1
  done
  [ -n "$THOST" ] || die "no tunnel URL, see $TLOG"
  # The server derives the origin it accepts logins for from its domain.
  export ATOMIC_DOMAIN="$THOST"
  URL="https://$THOST  (public while this runs)"
fi

phase "starting server on 0.0.0.0:$PORT"
"$BIN" --initialize >"$HOME_DIR/server-$SAFE.log" 2>&1 &
SP=$!
trap 'kill $SP ${TP:-} 2>/dev/null || true' EXIT INT TERM
for _ in $(seq 1 180); do
  kill -0 "$SP" 2>/dev/null || { tail -n 30 "$HOME_DIR/server-$SAFE.log"; die "server exited"; }
  [ "$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$PORT/")" = 200 ] && break
  sleep 1
done
phase "up: $URL  (log: $HOME_DIR/server-$SAFE.log, Ctrl-C to stop)"
wait "$SP"
