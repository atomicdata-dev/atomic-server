#!/usr/bin/env bash
#
# Runs the atomic-server the e2e suite talks to, against a data directory of its
# own.
#
# Which port? Whatever the data-browser is configured to talk to —
# `VITE_ATOMIC_SERVER_URL`, which defaults to 9883 in
# `browser/data-browser/vite.config.ts` and is overridden by
# `.env.development.local` if present. This is easy to get wrong: the suite's
# own `SERVER_URL` (default 9883) only points the test *helpers*, while the app
# the tests drive uses the vite env. Start a server on 9883 while the SPA is
# pointed at 9885 and every test fails on a connection refused that names neither.
#
# A shell export of `VITE_ATOMIC_SERVER_URL` is not visible here (it belongs to
# whoever started vite, not to this script), so pass `ATOMIC_E2E_SERVER_URL`
# when the app was started that way.
#
# Why a separate store: sharing yours means every run adds drives, tables and
# rows to the store you actually work in, and a store with a few hundred runs'
# worth of that makes the suite fail on timing rather than on bugs — the totals
# footer and the template specs start losing races they win in isolation. A red
# run then tells you nothing.
#
#   ./scripts/e2e-server.sh              # start; wipes the store if it is oversized
#   ./scripts/e2e-server.sh --fresh      # wipe the e2e store first, always
#   ./scripts/e2e-server.sh --keep-store # keep an oversized store (warns instead)
#   ./scripts/e2e-server.sh --stale-ok   # start even if the binary predates its sources
#   ./scripts/e2e-server.sh --mock-proxy # also run the mock integration proxy
#
# Safe to wipe: this directory only ever holds test data.
#
# Two things this refuses to let you do silently, because both produce a
# failure list that looks like real bugs and is not:
#   - run against a store big enough to fail specs on timing (it wipes it)
#   - run against a binary older than its sources (it stops and tells you)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
STORE="${ATOMIC_E2E_STORE:-$REPO_ROOT/.e2e-store}"

# Where does `cargo build` actually put the binary? NOT necessarily
# `$REPO_ROOT/target`: `CARGO_TARGET_DIR`, or a `build.target-dir` in any
# cargo config (commonly `~/.cargo/config.toml`, to share one target dir
# across checkouts or park it on a faster disk), moves it elsewhere. Guessing
# `$REPO_ROOT/target` is worse than it sounds — that path usually still holds
# a binary from before the config existed, so the suite starts, serves stale
# code, and fails specs for behaviour that was fixed weeks ago. Ask cargo
# instead of guessing; fall back to the conventional path when cargo can't
# answer (not installed, or a workspace it won't parse).
target_dir() {
  cargo metadata --no-deps --format-version 1 2>/dev/null \
    | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p'
}

# Prefer the `e2e` cargo profile, because that is what CI runs. `.dagger` builds
# the e2e server with `cargo build --locked --profile e2e`, and the workspace
# Cargo.toml defines that profile as release brought down to opt-level 2 with
# `debug-assertions` and `overflow-checks` deliberately left on. Its own comment
# says why: it is "an optimisation level where commit round-trips stop
# dominating".
#
# This script used to point straight at `target/debug`, and that is not a
# slower version of the same thing. At opt-level 0, with two Playwright workers,
# the app stops being able to BOOT: specs fail on a page whose whole snapshot is
# `img "AtomicServer"`, one of them after a 30s `waitForURL`, and the same file
# at `--workers=1` passes every time. Read as test failures those look like
# behaviour bugs or "CI shard contention", and they are neither. Anything
# concluded about timing from a debug binary is a measurement of the binary.
#
# A green on the slower build is still trustworthy, since a spec that passes at
# opt-level 0 passes at opt-level 2. A red is not evidence of anything.
if [[ -n "${ATOMIC_E2E_BINARY:-}" ]]; then
  BINARY="$ATOMIC_E2E_BINARY"
else
  TARGET_DIR="$(cd "$REPO_ROOT" && target_dir)"
  TARGET_DIR="${TARGET_DIR:-$REPO_ROOT/target}"
  if [[ -x "$TARGET_DIR/e2e/atomic-server" ]]; then
    BINARY="$TARGET_DIR/e2e/atomic-server"
  else
    BINARY="$TARGET_DIR/debug/atomic-server"
  fi
fi

ENV_DIR="$REPO_ROOT/browser/data-browser"

# The same files vite loads, in the same order it loads them: a developer's own
# `.env.development.local` wins, then the committed `.env.development`, then
# the default compiled into `vite.config.ts`.
#
# Reading only the `.local` file was wrong once `.env.development` was
# committed pointing somewhere else: the suite started a server on one port
# while the app it drives talked to another, and every test failed on a
# connection refused that named neither. The point of reading anything here is
# that the suite follows the app rather than guessing at it.
DEFAULT_SERVER_URL='http://localhost:9883'

read_server_url() {
  local found=''
  local file

  for file in "$ENV_DIR/.env.development.local" "$ENV_DIR/.env.development"; do
    [[ -f "$file" ]] || continue

    found=$(grep -E '^\s*VITE_ATOMIC_SERVER_URL=' "$file" | tail -1 | cut -d= -f2- | tr -d '"' | tr -d "'" | xargs || true)

    [[ -n "$found" ]] && break
  done

  echo "${found:-$DEFAULT_SERVER_URL}"
}

SERVER_URL="${ATOMIC_E2E_SERVER_URL:-$(read_server_url)}"

PORT="${SERVER_URL##*:}"
PORT="${PORT%%/*}"

if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
  echo "Could not read a port out of '$SERVER_URL'" >&2
  exit 1
fi

FRESH=false
KEEP_STORE=false
STALE_OK=false
MOCK_PROXY=false
MOCK_PROXY_PORT="${MOCK_PROXY_PORT:-19090}"

for arg in "$@"; do
  case "$arg" in
    --fresh) FRESH=true ;;
    --keep-store) KEEP_STORE=true ;;
    --stale-ok) STALE_OK=true ;;
    --mock-proxy) MOCK_PROXY=true ;;
    -h|--help)
      sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      echo "Usage: $0 [--fresh] [--keep-store] [--stale-ok] [--mock-proxy]" >&2
      exit 1
      ;;
  esac
done

# Checked before anything is wiped. This used to sit further down, after the
# `--fresh` wipe had already run: an older server still holding the port then
# kept serving a store that had just been deleted out from under it, and the
# suite ran green-looking nonsense against it for as long as nobody noticed.
# The failures that produces look like product bugs — `new-resource-catalog`
# lost its search box entirely — so nothing about them points at the cause.
# `lsof` alone was not safe to ask. A missing binary exits non-zero and the
# `2>&1` swallows "command not found", so a container without it concludes the
# port is free and walks straight into the wipe this check exists to prevent.
# Establish the tools first, then ask the question, and ask the one that
# actually matters: is anything answering on that port. `--noproxy` because an
# HTTPS_PROXY in the environment would otherwise send a localhost probe through
# it. `lsof` still runs when present, since a process can hold the socket
# without answering, and either answer means busy.
port_busy() {
  if [[ "$HAVE_CURL" == true ]] \
     && curl -s -o /dev/null --max-time 2 --noproxy '*' "$SERVER_URL"; then
    return 0
  fi

  if [[ "$HAVE_LSOF" == true ]] \
     && lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    return 0
  fi

  return 1
}

HAVE_CURL=false
HAVE_LSOF=false
command -v curl >/dev/null 2>&1 && HAVE_CURL=true
command -v lsof >/dev/null 2>&1 && HAVE_LSOF=true

if [[ "$HAVE_CURL" != true ]] && [[ "$HAVE_LSOF" != true ]]; then
  if [[ "$FRESH" == true ]]; then
    echo "Neither curl nor lsof is installed, so whether $PORT is already in use" >&2
    echo "cannot be established, and --fresh is about to delete $STORE." >&2
    echo "Refusing, rather than wiping on an assumption: a stale server holding" >&2
    echo "this port would go on serving a store that no longer exists, and the" >&2
    echo "failures that produces look like product bugs rather than like this." >&2
    echo "Install either tool, or run without --fresh." >&2
    exit 1
  fi

  # Nothing is being deleted, so an unnoticed stale server can only make the
  # new one fail to bind, which says so on its own.
  echo "Neither curl nor lsof is installed; skipping the port check." >&2
fi

if port_busy; then
  echo "Something is already listening on $PORT, and nothing has been wiped." >&2
  echo "If that is your dev server, stop it first — the suite needs that port," >&2
  echo "because it is the port the app is pointed at. If it is an older e2e" >&2
  echo "server, find it with:" >&2
  echo "  ps -eo pid,cmd | grep -E '[a]tomic-server$'" >&2
  echo "and kill it by pid. Do not reach for \`pkill -f atomic-server\`: the" >&2
  echo "pattern matches your own shell's command line too." >&2
  exit 1
fi

if [[ "$FRESH" == true ]]; then
  echo "Wiping $STORE"
  rm -rf "$STORE"
fi

if [[ ! -x "$BINARY" ]]; then
  echo "No server binary at $BINARY" >&2
  echo "Build one first:" >&2
  echo "  ATOMICSERVER_SKIP_JS_BUILD=true cargo build --profile e2e -p atomic-server" >&2
  echo >&2
  echo "Drop ATOMICSERVER_SKIP_JS_BUILD if you have not built the frontend yet;" >&2
  echo "keep it if you have, so build.rs embeds the dist you built rather than" >&2
  echo "replacing it with one built without VITE_E2E." >&2
  exit 1
fi

# Is the binary older than the sources that go into it? This matters more than
# it looks: `build.rs` embeds the data-browser bundle, and the invite and
# dev-drive pages are served from THAT copy rather than from vite. So a binary
# built on another branch serves one frontend on those pages and vite serves
# another everywhere else, and the specs that cross the boundary fail for
# reasons visible nowhere in their output. Checked against source mtimes rather
# than a commit date, so switching branches and editing a file both count.

# Generated files live under `src/` but are not sources: wuchale rewrites the
# locale catalogs (`src/locales/data.js`, `src/locales/main.loader.js`,
# `src/locales/.wuchale/*`) on every vite start, byte-for-byte identical.
# Counting those as "newer sources" made both checks below fire every time
# anyone had run `pnpm start`, which teaches you to pass `--stale-ok` reflexively
# — and that is the flag that lets a genuinely stale build through.
stale_source() {
  find "$REPO_ROOT/server/src" \
       "$REPO_ROOT/lib/src" \
       "$REPO_ROOT/browser/data-browser/src" \
       "$REPO_ROOT/browser/lib/src" \
       -type f \
       -not -path "*/src/locales/.wuchale/*" \
       -not -path "*/src/locales/data.js" \
       -not -path "*/src/locales/main.loader.js" \
       -newer "$BINARY" -print -quit 2>/dev/null
}

# The binary being fresh is not the same as the EMBEDDED BUNDLE being fresh:
# `build.rs` skips the JS build when it thinks `dist` is current, so a rebuilt
# binary can still carry an old frontend. Check the bundle on its own terms.
BUNDLE="$REPO_ROOT/browser/data-browser/dist/index.html"

stale_bundle() {
  [[ -f "$BUNDLE" ]] || return 1

  find "$REPO_ROOT/browser/data-browser/src" \
       "$REPO_ROOT/browser/lib/src" \
       -type f \
       -not -path "*/src/locales/.wuchale/*" \
       -not -path "*/src/locales/data.js" \
       -not -path "*/src/locales/main.loader.js" \
       -newer "$BUNDLE" -print -quit 2>/dev/null
}

if [[ "$STALE_OK" != true ]] && [[ -n "$(stale_bundle)" ]]; then
  echo "The embedded frontend bundle is older than the sources it is built from." >&2
  echo "  bundle: $BUNDLE" >&2
  echo "  newer:  $(stale_bundle)" >&2
  echo >&2
  echo "The invite and dev-drive pages are served from that bundle, not from" >&2
  echo "vite, so they would run stale code while every other page runs current" >&2
  echo "code. Rebuild it:" >&2
  echo "  cargo build --profile e2e -p atomic-server" >&2
  echo >&2
  echo "If that leaves the bundle untouched, something non-bundle in dist/ is" >&2
  echo "newer than your sources and build.rs is skipping the JS build; build" >&2
  echo "the frontend directly with 'pnpm --filter @tomic/data-browser build'." >&2
  echo >&2
  echo "Pass --stale-ok to start anyway." >&2
  exit 1
fi

if [[ "$STALE_OK" != true ]] && [[ -n "$(stale_source)" ]]; then
  echo "The server binary is older than the sources it is built from." >&2
  echo "  binary: $BINARY" >&2
  echo "  newer:  $(stale_source)" >&2
  echo >&2
  echo "Rebuild it (this also refreshes the embedded frontend bundle):" >&2
  echo "  cargo build --profile e2e -p atomic-server" >&2
  echo >&2
  echo "Pass --stale-ok to start anyway. That is fine when the specs you are" >&2
  echo "running only touch vite-served pages; it is not fine for anything" >&2
  echo "going through invite, dev-drive, or a server-side plugin hook." >&2
  exit 1
fi

mkdir -p "$STORE"

# The store degrades the suite surprisingly fast: measured on this repo,
# `aggregates.spec.ts` passes in 10s on a fresh store and fails outright on a
# 324MB one, which is about two full suite runs' worth. Say so, because the
# failure mode looks nothing like its cause.
# This used to print a note and carry on. A note is the wrong shape for this:
# the usual way to start this server is in the background with output going to
# a log, so nobody reads it, and the reward for missing it is a failure list
# that changes every run. Wipe instead — the directory only ever holds test
# data, and one full suite is enough to cross the line.
SIZE_MB=$(du -sm "$STORE" 2>/dev/null | cut -f1 || echo 0)

if [[ "$SIZE_MB" -gt 150 ]] && [[ "$FRESH" != true ]]; then
  if [[ "$KEEP_STORE" == true ]]; then
    echo
    echo "WARNING: the e2e store is ${SIZE_MB}MB and --keep-store was passed."
    echo "         Past ~150MB specs start failing on timing rather than on"
    echo "         bugs, and the set changes run to run. Do not trust a failure"
    echo "         list from this store without reproducing it on a fresh one."
    echo
  else
    echo "The e2e store is ${SIZE_MB}MB — past the ~150MB point where specs"
    echo "start failing on timing. Wiping it (pass --keep-store to keep it)."
    rm -rf "$STORE"
    mkdir -p "$STORE"
  fi
fi

echo "Serving e2e on $SERVER_URL with its own store at $STORE"
echo "Run the tests with a matching helper URL:"
echo "  SERVER_URL=$SERVER_URL pnpm test-e2e"

# Website publishing is off until the server is given a site origin, and the
# website specs then get a "hosting is disabled" toast that also sits over the
# preview and swallows clicks meant for it. Same value the CI e2e service uses.
export ATOMIC_WEBSITE_ORIGIN="${ATOMIC_WEBSITE_ORIGIN:-http://sites.localhost:$PORT}"

# `ATOMIC_REPOPULATE_DEFAULTS` so an existing e2e store picks up vocabulary added
# since it was created: a store seeded before a Property existed can never
# receive it otherwise, and every test using that Property fails on a 404 that
# looks nothing like the cause.
# No spec in this repo needs an integration proxy any more: the provider
# integrations and their specs moved to atomic-plugins, and CI no longer runs
# one. `--mock-proxy` still starts `mock-proxy.mjs` beside the server for
# manual LocalThought testing against a local proxy.
if [[ "$MOCK_PROXY" == true ]]; then
  PROXY_URL="http://127.0.0.1:$MOCK_PROXY_PORT"

  # The browser reads the proxy URL from localStorage at runtime, and
  # playwright seeds that key from `INTEGRATION_PROXY_URL` (see
  # playwright.config.ts). No rebuild is involved, so any port works with a
  # bundle that was never built against it — say which value to pass rather
  # than letting the specs fail as if the proxy were down.
  echo "Run the integration specs against this proxy with:"
  echo "  INTEGRATION_PROXY_URL=$PROXY_URL SERVER_URL=$SERVER_URL pnpm test-e2e"

  MOCK_FRONTEND_ORIGIN="${MOCK_FRONTEND_ORIGIN:-$SERVER_URL}" \
  MOCK_PROXY_HOST="${MOCK_PROXY_HOST:-127.0.0.1}" \
  MOCK_PROXY_PORT="$MOCK_PROXY_PORT" \
    node "$REPO_ROOT/integrations/localthought/mock-proxy.mjs" &
  MOCK_PROXY_PID=$!
  trap 'kill "$MOCK_PROXY_PID" 2>/dev/null || true' EXIT

  # Started is not running. A proxy that failed to bind leaves exactly the
  # silent wrong results this flag exists to prevent, so wait for it to answer
  # and refuse to continue if it never does.
  for _ in $(seq 1 30); do
    if curl -fsS -o /dev/null "$PROXY_URL/catalog"; then
      echo "Mock integration proxy answering on $PROXY_URL"
      break
    fi
    if ! kill -0 "$MOCK_PROXY_PID" 2>/dev/null; then
      echo "The mock integration proxy exited while starting." >&2
      exit 1
    fi
    sleep 1
  done

  if ! curl -fsS -o /dev/null "$PROXY_URL/catalog"; then
    echo "The mock integration proxy never answered on $PROXY_URL/catalog." >&2
    echo "Refusing to start: the integration specs would fail as if the" >&2
    echo "product were broken." >&2
    exit 1
  fi

  # Deliberately nothing else. The server is given no proxy environment at all:
  # the browser reaches the proxy directly, and the server never needs to know
  # it exists. Copying what `.dagger` gives its e2e service
  # (ATOMIC_INTEGRATION_PROXY_URL, ATOMIC_MOCK_INTEGRATION_PROXY, TENANT_SECRET,
  # ATOMIC_INTEGRATION_FRONTEND_ORIGIN) is not neutral here: measured on
  # 20 September 2026 it took plugins.spec.ts from 2 failures to 4, and the two
  # it added were `:109` and `:514`, neither of which has anything to do with an
  # integration provider. Those variables belong to a container this is not.
fi

SERVER_ENV=(
  ATOMIC_DATA_DIR="$STORE/data"
  ATOMIC_CONFIG_DIR="$STORE/config"
  ATOMIC_CACHE_DIR="$STORE/cache"
  ATOMIC_PORT="$PORT"
  ATOMIC_DOMAIN=localhost
  ATOMIC_REPOPULATE_DEFAULTS=true
)

# Foreground rather than `exec` when there is a proxy to clean up afterwards:
# `exec` replaces this shell, and its EXIT trap goes with it, leaving the proxy
# running to claim the port on the next start.
if [[ "$MOCK_PROXY" == true ]]; then
  env "${SERVER_ENV[@]}" "$BINARY"
else
  exec env "${SERVER_ENV[@]}" "$BINARY"
fi
