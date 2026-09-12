# AGENTS.md

Guidance for coding agents working in this repo.

## Local Setup

- `http://localhost:6747` — Vite dev server (frontend). (`cd browser && pnpm dev`)
- `http://localhost:9883` — local AtomicServer. (`cd server && cargo run`)

The frontend auto-updates via HMR. If changes don't appear, reload the page. If you edit `@tomic/lib` or `@tomic/react`, those packages may need a rebuild first.

## Planning

Use the `./planning` folder to write plans and keep track of progress.
Use todo lists and checkboxes to track progress.
Make sure to update the planning as you find new insights and see outdated planning text.
Remove planning documents that are completed.

## Git

Default branch is `develop`. Open PRs against it. Staging deploys from `develop`
after green CI; production and live docs deploy from a stable `v*` tag. Do not
introduce a `main` branch, treat `master` as production, or add a job that
fast-forwards `main` when a tag is pushed — the tag is the release. Hotfixes
branch from the tag and merge back to `develop`. See `CONTRIBUTING.md`.

**Stop the vite dev server before any git operation that rewrites files** — a
rebase, a branch switch, a `git checkout -- .`. See below for why.

## Translation catalogs (`src/locales/*.po`)

Wuchale extracts these from source *as vite serves it*, so the dev server is a
second writer on tracked files. Four ways that has cost real time:

- **During a rebase.** The extractor rewrote the `.po` files between steps, so
  git reported "You must edit all merge conflicts" while `git diff` showed
  nothing unmerged. Stop vite first.
- **Two writers.** Two dev servers, or a dev server plus a build, race on the
  same catalogs and corrupt them. Symptom: `[i18n-404:NNN]` where a label
  should be. One vite at a time — a worktree has its own catalogs, so one per
  worktree is fine.
- **Catalogs that are not the extractor's fixed point.** If what is committed
  differs from what extraction produces, every dev-server start rewrites them,
  vite sees a file change, and the page reloads. That is not cosmetic: a reload
  abandons in-flight work, and this silently cancelled a destroy mid-test. If
  `git status` shows `.po` churn on a clean checkout, settle them and commit.
- **`pnpm clean-translations` is not the same writer.** It extracts from test
  files too, which the vite plugin does not, so its output is a *different*
  fixed point. Settling by running the app is what matches the dev server.

Strings a model reads — tool descriptions, prompts, instructions — must be
`@wc-ignore`d. A translated tool name is not a tool name. See
`browser/data-browser/CLAUDE.md` for the ignore syntax.

After touching anything that renders text, read the `.po` diff by hand: a
guarded element can silently drop sibling strings, and entries re-key when an
icon moves into a message.

## Quick Dev Setup

Use the Charlotte MCP server and navigate to `http://localhost:6747/app/dev-drive` to instantly create a fresh agent.

In E2E tests, most specs use `test.beforeEach(before)` from `test-utils.ts`, which calls `devDrive(page)` and gives every test a fresh agent + drive. For a second browser context signed in as the same user, use `getDevDriveSecret(page)` after `before` has run. Call `devDrive(page)` directly only when a spec does not use the shared `before` hook.

## Charlotte / Browser Automation

- Operate the app at `localhost:6747` for quick iterations on react code.
- Start every session by navigating to `http://localhost:6747/app/dev-drive` to get a clean, authenticated state.
- If the app shows `Unauthorized` or `Something went wrong`, navigate to `/app/dev-drive` to fix it.

## Debugging process

1. Identify the bug, where it's coming from.
2. Reproduce the bug in a test at the cheapest layer that can fail: Rust /
   vitest first, then `browser/lib` `*.integration.test.ts` (real server, no
   UI), then one Playwright test. E2E is the most expensive. Tag `@smoke`
   (`smoke` in `browser/e2e/tests/test-utils.ts`) only if a failure means the
   first-hour demo is dead; extra operators and offline variants stay in the
   full suite. See `planning/e2e-light-heavy.md`.
3. After reproduction in a failing test, fix the bug until the test and all other tests are green again

## DevTools Console Helpers

In dev mode, `window.devtools` exposes diagnostics for inspecting a resource across every persistence layer. Run `devtools.help()` for the list. Most useful:

| call                         | what it does                                                                                                |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `devtools.inspect(subject?)` | JS store + WASM/OPFS + server HTTP GET, side-by-side. Defaults to the URL's `?subject=` (or current drive). |
| `devtools.opfsList(prefix?)` | Subjects in the WASM DB (default prefix `did:ad:`)                                                          |
| `devtools.wsLog(n?)`         | `console.table` of the last N commit log entries                                                            |
| `devtools.problems()`        | Resources currently loading, errored, or new                                                                |
| `devtools.forcePut(subject)` | Re-serialize a JS-store resource into OPFS with round-trip verification                                     |

Source: `browser/data-browser/src/helpers/devtools.ts`.

## Architecture Overview

Atomic Server is a graph database with real-time sync, built on **Loro CRDT** for conflict-free collaborative editing.

### Crates

- **`docs`** (`docs`) — Public-facing Atomic Data spec and product documentation. Describes how the protocol works, very important.
- **`planning`** (`planning/`) — Internal design notes and larger technical direction. Read `planning/README.md` and the relevant plan before broad architectural work.
- **`atomic_lib`** (`lib/`) — Core library powering atomic-server + WASM / OPFS browser storage.
- **`atomic-server`** (`server/`) — Actix-web HTTP/WS server. Uses `atomic_lib` (KV full-text search + optional LanceDB vector search).
- **`@tomic/lib`** (`browser/lib/`) — TypeScript client library, powering the other JS projects
- **`@tomic/react`** (`browser/react/`) — React hooks.
- **`data-browser`** (`browser/data-browser/`) — The web app (React + TipTap + Loro), feels similar to notion. See the related AGENTS.md
- **`flutter/`** — Cross-platform canvas app (Android/iOS/Web). Uses `flutter_rust_bridge` to call `atomic_lib`. See `flutter/README.md` and `flutter/AGENTS.md`.

### Data model

- **Resource** = property-value pairs with a Subject URL, backed by a Loro CRDT document.
- **Commit** = a signed mutation containing `loroUpdate` (base64 Loro binary).
- **Agent** = Ed25519 keypair, identified by `did:ad:agent:{publicKey}`.
- **Drive** = top-level container resource.

## Loro CRDT — How It Works

**Loro is the sole state management engine.** The old `set`/`remove`/`push` commit fields are deprecated and rejected by the server.

### Client side (TypeScript)

1. `resource.set(prop, value)` → writes to LoroDoc's `"properties"` map + sets `_dirty`
2. `resource.save()` → `exportLoroDelta()` → base64 → commit `loroUpdate` → sign → POST
3. Incoming WS commits: `execLoroUpdateCommit()` imports Loro binary into resource's LoroDoc, materializes properties into propvals

### Server side (Rust)

1. Commit arrives at `/commit`
2. `apply_changes()` imports `loroUpdate` into resource's LoroDoc
3. `import_update_with_diff()` computes add/remove atoms for search indexing
4. `loro_value_to_atomic_value_tagged()` materializes Loro values to Atomic `Value` types, using the `datatypes` map
5. Loro snapshot stored alongside PropVals for future merges

### Loro value serialization in the Map

The LoroDoc has two sibling root maps:

- **`properties`** — `property URL → value`. Loro primitives stored directly
  (strings, numbers, booleans); arrays as native `LoroList`s; objects as JSON strings.
- **`datatypes`** — sparse `property URL → tag`, recording the datatype only
  where a bare primitive is ambiguous in a load-bearing way. Tags: `atomicUrl`,
  `resourceArray`, `json`, `resource`. Scalars and plain/cosmetic
  strings carry no entry. Written by `set_property` (Rust) and
  `Resource.writeDatatypeTags` at sign time (TS).

Materialization prefers the tag: `loro_value_to_atomic_value_tagged()` recovers
the exact `Value` variant from it. Untagged values fall back to the
`loro_value_to_atomic_value()` heuristic (URL-shaped strings → `AtomicUrl`,
`{...}` → `NestedResource`), kept for legacy / not-yet-tagged docs. Cosmetic
datatypes (`markdown`/`slug`/`date`/`uri`, `timestamp`) are deliberately not
tagged — they collapse to `string`/`integer`; the Property's `datatype` stays
authoritative. See `planning/loro-source-of-truth.md`.

### Critical: always build on existing state

When editing a resource, load the existing Loro snapshot first, then edit on top. Creating a fresh LoroDoc for each edit causes LWW conflicts. The `CommitBuilder` on the server converts `set`/`remove` to Loro at sign time via `sign_at()`.

## Commit Structure

```json
{
  "https://atomicdata.dev/properties/subject": "did:ad:{genesis}",
  "https://atomicdata.dev/properties/signer": "did:ad:agent:{publicKey}",
  "https://atomicdata.dev/properties/loroUpdate": "base64...",
  "https://atomicdata.dev/properties/signature": "base64...",
  "https://atomicdata.dev/properties/createdAt": 1775504552928,
  "https://atomicdata.dev/properties/previousCommit": "did:ad:commit:{sig}",
  "https://atomicdata.dev/properties/isGenesis": true
}
```

- `loroUpdate` is a plain base64 string (not a `{type, data}` object)
- `set`, `push`, `remove` are **rejected** by the server
- Signature: deterministic JSON-AD (sorted keys, minified, no `@id`, no signature field)
- Genesis commits: `subject` excluded from signed bytes (derived from signature)

## Subject Type

`Subject` is an enum: `Internal` (`internal:/path`), `External` (`https://...`), `Did` (`did:ad:{genesis}`).

`Commit.subject` and `Commit.signer` are `Subject`, not `String`.

Equality is by URL string only — `drive_hint` and `subdomain` don't affect identity (custom `PartialEq`/`Hash`).

## WebSocket Protocol

Binary frames `[tag][payload]` (`lib/src/sync/protocol.rs`, mirrored in
`browser/lib/src/ws-v2.ts`; spec in `docs/src/websockets.md`):

| Frame                        | Direction | Purpose                                   |
| ---------------------------- | --------- | ----------------------------------------- |
| `AUTH (0x01)`                | C→S       | Auth, answered by `AUTH_OK` / `ERROR`     |
| `SUB (0x20)`                 | C→S       | Commit notifications for a drive/resource |
| `UPDATE (0x11)`              | S→C       | Applied commit (Loro delta or snapshot)   |
| `COMMIT (0x13)`              | C→S       | Persist a signed commit                   |
| `SYNC (0x30)` family         | Both      | Drive reconcile                           |
| `EPHEMERAL (0x40)`           | Both      | Edits in progress, cursors, presence      |
| `LORO_SYNC_SUBSCRIBE {json}` | C→S       | Text: register for a resource's ephemera  |
| `PRESENCE_SUBSCRIBE {json}`  | C→S       | Text: register for a drive's presence     |

**Pattern:** Subscribe to broadcast BEFORE sending a message that expects a response.

## Cryptography

Uses **ed25519-dalek** (pure Rust, WASM-compatible). Server keeps `ring` for TLS only.

## Resource (Rust)

```rust
pub struct Resource {
    propvals: PropVals,              // Read cache
    subject: Subject,
    commit: CommitBuilder,           // Legacy server-side
    loro: Option<AtomicLoroDoc>,     // CRDT doc, lazy
}
```

- `save()` — server-side (CommitBuilder → Loro → apply locally)
- `save_remote(store)` — client-side (propvals → Loro → export → sign → HTTP POST)
- `save_as_genesis(store)` — DID resource, subject = `did:ad:{signature}`

## Rich Text

TipTap + `loro-prosemirror` (`LoroSyncPlugin`, `LoroUndoPlugin`, `LoroEphemeralCursorPlugin`).
Real-time: `useLoroSync` hook → `EPHEMERAL` (kind `DOC`) over WebSocket.

## History Page

Loro OpLog time-travel: `doc.getAllChanges()` → sort → `doc.checkout(frontiers)` per version. Instant, no network round-trips.

## Iroh P2P Sync

Devices sync via [Iroh](https://iroh.computer) QUIC connections. The transport is in `lib/src/sync/`:

- **`peer.rs`** — Iroh endpoint, Router (must stay alive for incoming connections), persistent NodeID (secret key stored in redb), known peers list.
- **`engine.rs`** — Transport-agnostic sync engine. Compares Loro version vectors, computes diffs, imports snapshots. Used by both WS and Iroh.
- **`protocol.rs`** — Binary frame encoding: AUTH, SYNC, SYNC_DIFF, SYNC_PUSH, SYNC_OK, GET, UPDATE.

### Sync flow (QR pairing)

1. Both devices start Iroh (`peer::start()`) → get persistent NodeID, connect to n0 relay
2. Device A shows QR code containing `did:ad:node:<nodeId>`
3. Device B scans QR → calls `peer_sync(nodeId)` → `sync_drive_with_peer()`
4. B→A: AUTH, SYNC (with B's version vectors)
5. A→B: SYNC_DIFF (what to push/pull), SYNC_PUSH (A's data)
6. B→A: SYNC_PUSH (B's data for A's pull list)
7. Both devices now have each other's data

### Key details

- The `Router` must be kept alive globally (`ROUTER` static) — dropping it stops incoming connections.
- After sending the final SYNC_PUSH, call `send.finish()` + short delay so the server processes it before the connection drops.
- Loro snapshots are stored in `Tree::LoroSnapshots` keyed by `Subject::pure_id()` (strips query params/drive hints).
- `collect_drive_subjects()` and `build_drive_vvs()` must use `pure_id()` consistently to match snapshot keys.

### Node identity

- `did:ad:node:<hex>` — URI format for Iroh NodeIDs, used in QR codes and UI.
- NodeIDs are persistent — derived from a secret key stored in redb (`Tree::PluginMeta`).
- Known peers are also stored in `Tree::PluginMeta` as a JSON array.

## Testing

[`TESTING_COVERAGE.md`](./TESTING_COVERAGE.md) maps which flows are tested at
which layer, and — more usefully — which are not. Read it before deciding where
a new test belongs, and update it when you add one or discover a gap.

```
cargo test -p atomic_lib --features db-redb --lib # unit tests (needs the `db` feature)
cargo test -p atomic-server --lib
cargo test -p atomic-server --test sync          # integration test: real server, 2 agents, WS sync
cargo test -p atomic_lib --features "iroh,discovery,db-redb" --lib -- sync::tests  # Iroh sync tests (incl. live sync)
cargo test -p atomic_lib --features "iroh,db-redb" --lib -- sync::iroh_e2e -- --test-threads=1  # Iroh e2e: bulk + live + folderId
cargo test -p atomic_lib --features db-redb,iroh --test identity_durability  # identity/peers survive an unclean kill
cargo test -p atomic_lib --features db-redb,iroh --test cross_process_sync   # two OS processes reconcile over Iroh
cargo test -p atomic-server --test it iroh_pairing  # two servers pair via POST /iroh-sync
cargo test --manifest-path flutter/rust/Cargo.toml  # Flutter bridge (workspace-excluded, needs --manifest-path)
cd browser/lib && pnpm test                      # JS unit tests
cd browser && pnpm run -r build                  # Full workspace build
cd browser && pnpm run test-e2e:light            # Playwright @smoke (feature-branch CI)
cd browser && pnpm run test-e2e                  # Full Playwright suite (develop / tags)
```

`atomic_lib`'s unit tests need the `db` feature — `hierarchy.rs`'s test module
calls `Db::init_temp` and `test_utils::setup_test_env`, both gated behind it. So
`cargo test -p atomic_lib --no-default-features` does **not** compile; don't
reach for it. CI never trips on this because it tests the whole workspace at
once (`.dagger` `rustTest`), where `atomic-server`'s unconditional `atomic_lib`
dependency (`features = ["db-redb", ...]` in `server/Cargo.toml`) turns `db` on
via feature unification. `--lib` is load-bearing too: the `list_sled_trees`
example needs `sled`, which only `db-sled` provides.

## Cursor Cloud specific instructions

The startup update script only runs `pnpm install` (in `browser/`). Everything below is
already handled in the VM snapshot; these notes capture the non-obvious gotchas for
building/running the stack again after pulling changes.

### Run the server on the port the frontend is pointed at

`browser/data-browser/vite.config.ts` defaults `VITE_ATOMIC_SERVER_URL` and points the
Vite proxy at the same value, so the app and the proxy always agree with each other. The
server has to be started on that port too, which is 9883 by default:

```
/workspace/target/debug/atomic-server --port 9883            # subsequent runs
/workspace/target/debug/atomic-server --port 9883 --initialize   # first run / to reset the /setup invite
```

If the three disagree, the app silently repoints drives to a server that isn't listening
and auth/drive resolution fails. Then open `http://localhost:6747/app/dev-drive` for a
clean authenticated agent + drive.

A wrapper that runs its own node overrides the app's port by exporting
`VITE_ATOMIC_SERVER_URL` (vite prefers a `VITE_`-prefixed process variable over the env
files), and starts its node there instead. Check what the dev server printed before
assuming 9883.

### pnpm scripts need bash (`build:wasm` breaks under dash)

`data-browser`'s `build:wasm` uses `CARGO_ENCODED_RUSTFLAGS=$'--cfg\x1f...'` (bash ANSI-C
quoting). The VM's `/bin/sh` is `dash`, which doesn't understand `$'...'`, so pnpm scripts
must run under bash. This is configured once (persisted in `~/.config/pnpm/rc`):

```
pnpm config set script-shell /usr/bin/bash
```

If `pnpm build:wasm` ever fails with `error: multiple input filenames provided (... $--cfg\x1f...)`,
re-run that config command.

### WASM build is required before the frontend works

`browser/data-browser/public/wasm/{atomic_wasm.js,atomic_wasm_bg.wasm}` are git-ignored and
must be generated (needs the `wasm32-unknown-unknown` target, already installed):

```
pnpm --filter @tomic/data-browser build:wasm
```

Only re-run this when the `wasm/` or `lib/` Rust changes; it is not part of `pnpm start`.

### Running the frontend

`cd browser && pnpm start` runs `@tomic/lib` + `@tomic/react` (tsup watch) and the Vite dev
server (`:6747`) together. During `vite dev` you may see React Compiler warnings from
`oxc-transform-react` (try/catch, `finally`, ref-during-render, and similar
Rules of React violations). Those are non-fatal: the compiler skips
auto-memoizing that component and the app still serves and HMRs normally.

### Services summary

| Service | Dir | Dev command | Port |
| --- | --- | --- | --- |
| AtomicServer (Rust: HTTP/WS, redb, Loro sync) | `server/` | `cargo run -- --port 9885` | 9885 |
| Frontend (Vite) + `@tomic/lib`/`@tomic/react` watch | `browser/` | `pnpm start` | 6747 |
