# Testing coverage map

What is tested, at which layer, and — the part that matters — **what is not**.

This exists because the protocol is far better tested than the glue around it,
and that imbalance is invisible from a passing CI run. Every production bug in
device sync so far has been in a layer this document lists as uncovered.

**Keep it current.** When you add a test, add the row. When you find a blind
spot, write it down even if you are not fixing it today — an admitted gap is
worth more than a forgotten one. When you fix a bug, ask which row would have
caught it, and if the answer is "none", that is the row to add.

---

## How to read this

Clockify: `integrations/clockify/plugin.test.ts` covers linked proposals, time
instants, repeat imports, pagination and failure handling.
`plugins::clockify_tests::completed_entries_are_proposals_in_the_real_sandbox`
runs the shipped bundle in the real Rust sandbox with a fixture provider. A second
Clockify sandbox test verifies discovery and minimized response fields.
`plugins.spec.ts` covers named workspace discovery, date selection, schema/table
creation and visible preview transport failures. All offline certification layers
pass. `clockify-import.integration.test.ts` applies proposals through the real TS Store
with mocked HTTP, verifies signed Loro updates, final Project/Person DID links,
and skips records on repeat import. Planner regressions cover temporary in-plan
links, class constraints and rejection of unrelated temporary subjects. The shared
`plugin-server.test.ts` covers signed execution, malformed responses and errors.
A second Clockify browser test runs discovery/mapping inside the real sandbox,
approves three linked resources into the local server and reruns against its DB
with no duplicate proposals. It reuses an existing Time Tracker, preserves its
views and customized property name, and opens it through the completed setup.
The same browser flow asserts that supporting records are children of the app,
then previews/applies a legacy root-level project's move back into it and verifies
a no-op repeat. Fixture tests reject moving manually organized or unrelated data.
Live installed-source upgrade and cleanup of the user's earlier root records have
not been performed.
`integrations/clockify/atomic.test.ts` checks read-only table compatibility by
identity, datatype, required fields and related-class constraints. Only provider HTTP is replaced with synthetic data;
this does not certify actual Clockify access or the host HTTP permission layer.
Live provider reads, regional origins and two-way sync remain unverified or
unimplemented.

Integration maintenance: `node integrations/tooling/certify.mjs` automatically
discovers provider packages, verifies reproducible shipped bundles and types,
runs fixture suites and exact Rust sandbox tests, and exports JSON evidence.
`integrations/tooling/certify.test.mjs` covers zero-test refusal and missing
metadata. Dagger's JS gate discovers provider packages, while Rust includes all provider
fixtures. Reports explicitly distinguish selected offline layers and unrun live
checks. GitHub's compatible code-only upgrade preserves bindings and prevents
replacement of pending effects across upgrade/rollback. Mapping migrations and
scheduled live canaries remain uncovered. Evidence guards reject changed bundles,
partial/failed reports and invalid dates; old results are labelled. The Notion
setup browser test opens all three bundled cards' offline evidence disclosures.

Integration UX: `plugins.spec.ts` covers search before credential setup, lazy
GitHub/Notion dialogs, and creating an automation from a connected integration.
It edits JavaScript, saves and reviews a real proposed effect, enables execution,
returns to review mode and checks history. The trigger HTTP response regression
`response_filters_round_trip_into_updates` ensures GET filter values can be sent
back to POST; tagged database values previously broke the enable button.
The Pets flow verifies the bundled card's title and setup label, installs its
connection, approves its five proposed creates, and finds Rex, Whiskers, Tweety,
Nibbles and Bubbles in the resulting table.
Run it against a production build to catch missing translation catalog entries:
Vite dev extracts them automatically and can hide blank production labels.
The GitHub setup flow also covers opting into assistant-led automation creation:
request and integration context survive a model-setup handoff, and source editing
stays collapsed. A unit test checks draft/context binding. The advanced path still
tests save, sample review and enablement. These checks do not call a live LLM or
certify generated JavaScript quality.

Coverage is split by *layer*, because the same flow can be well covered in one
and absent in another:

| Layer | Meaning |
|---|---|
| **protocol** | `atomic_lib` sync engine — the bytes on the wire |
| **glue** | the code wrapping the protocol: HTTP handlers, the Flutter bridge, browser helpers |
| **flow** | what a user actually does, end to end, through a UI |

A flow is only genuinely safe when all three are covered.

### Playwright light vs full

Only the browser suite splits. Lint, Rust, vitest, JS integration, and
Flutter run on every CI job.

| Trigger | Playwright |
|---|---|
| Feature-branch push | **light** (`@smoke`), required |
| `develop` push | **full**, required (staging) |
| stable `v*` tag | **full**, required (production) |
| `workflow_dispatch` `e2e_mode=full`, `[full-e2e]` in the commit, or PR label `full-e2e` | **full** |

Tag a new journey `@smoke` (`smoke` from `browser/e2e/tests/test-utils.ts`)
only if a failure means the first-hour demo is dead. Extra operators,
templates, and offline variants stay in the full suite. Policy:
[`planning/e2e-light-heavy.md`](./planning/e2e-light-heavy.md).

---

## Where the suites live

| Suite | Command | CI job |
|---|---|---|
| `atomic_lib` unit + integration | `cargo nextest run -p atomic_lib --features db-redb,iroh,ws` | `rustTest` |
| Server integration | `cargo test -p atomic-server --test it <module>` | `rustTest` |
| Browser unit (vitest) | `cd browser && pnpm run -r test` | `jsTest` |
| Browser integration (vitest + real server) | `cd browser/lib && pnpm run test:integration` | `jsTestIntegration` |
| Browser e2e light (`@smoke`) | `cd browser && pnpm run test-e2e:light` | `endToEnd` on feature branches |
| Browser e2e full | `cd browser && pnpm run test-e2e` | `endToEnd` on `develop` and `v*` tags |
| Flutter Dart | `cd flutter && flutter test` | `flutterTest` |
| Flutter Rust bridge | `cargo test --manifest-path flutter/rust/Cargo.toml` | `flutterTest` |

CI runs `cargo nextest run --workspace --exclude atomic-server-tauri
--no-default-features --features light`. Feature unification pulls in
`db-redb` + `iroh`, so feature-gated sync tests do run there.

Two things worth knowing about the runners:

- **`flutter/rust` is excluded from the workspace** (root `Cargo.toml`), so
  `--workspace` never compiles it. It is covered only by the explicit
  `--manifest-path` step in `flutterTest`.
- **`.config/nextest.toml` sets `retries = 2`.** A flaky test passes CI
  silently. Check for `FLAKY` in nextest output, not just the summary line.

---

## Sync and pairing

### Protocol — well covered

| Flow | Where |
|---|---|
| Two Iroh nodes reconcile (bulk + live) | `lib/src/sync/iroh_e2e.rs` (13 tests, real QUIC) |
| Stroke appended after sync propagates | `lib/src/sync/iroh_e2e.rs` |
| A peer only receives what its agent may read | `iroh_e2e.rs`, `peer.rs` |
| A peer cannot forge a third agent's resource | `iroh_e2e.rs` |
| Relayed write accepted only for a drive we own and dialled | `peer.rs` |
| Iroh accept side refuses any frame before `AUTH` (ERROR + closed stream), binds `AUTH.requestedSubject` to the handshake drive | `peer.rs` (`accept_gate_tests`, raw QUIC stream) |
| Rejected `SYNC_PUSH` answers `ERROR SYNC_REJECTED`, never `SYNC_OK` | `peer.rs` (`accept_gate_tests`), `server/tests/it/ws_auth_gate.rs` |
| WS: writes and identity-bearing subscriptions need `AUTH`; anonymous `SUB` on a public drive still works; unreadable subscriptions answer `ERROR UNAUTHORIZED_READ` | `server/tests/it/ws_auth_gate.rs` |
| Missing-drive bootstrap (OQ5): `Public` never creates a drive, Owner mode enrolls only the owner, open node admits an authenticated first-sync | `lib/src/sync/engine.rs` (`bootstrap_and_sub_tests`), `peer.rs` (`live_write_admission_tests`) |
| Engine-owned `SUB`/`UNSUB`: granted `SUB` is a session command, unreadable `SUB` answers `ERROR UNAUTHORIZED_READ` | `lib/src/sync/engine.rs` (`bootstrap_and_sub_tests`) |
| Signed `SYNC_DIFF.removeCommits`: envelope applies regardless of connection agent, tampered envelope does not delete, envelope only handed to drive readers, replay after re-creation refused | `lib/src/sync/peer.rs` (`initiator_trust_tests`), `engine.rs` (`bootstrap_and_sub_tests`), `tombstones.rs`, `protocol.rs` |
| `SyncSession` over an in-process `AtomicTransport` holds `AUTH` across frames | `lib/src/sync/session.rs` |
| Signed envelopes per resource: `latest`/`all` retention, time order, not indexed, verified attribution per Loro token, tampered envelope unverified, two writers, destroy fold | `lib/src/envelopes.rs` |
| `GET /history-attribution` names the verified signer and is read-gated | `server/tests/it/history_attribution.rs` |
| Attribution parse / version lookup / server+local merge | `browser/lib/src/history-attribution.test.ts` |
| Engine-level two-store sync, private drives, blobs, live push | `lib/src/sync/tests.rs` |
| RBSR reconciliation, drive hashing | `lib/src/sync/rbsr.rs`, `tests.rs` |
| RBSR finds a remote-only subject sorting below every local one | `lib/src/sync/rbsr.rs` **and** `browser/lib/src/rbsr.test.ts` (regression, see below) |
| Remote update merge, drive-spoof rejection, tombstones | `lib/src/sync/ws_apply.rs`, `tombstones.rs` |
| Pairing envelope encode/decode | `browser/lib/src/pairing.test.ts` |

### Cross-process — covered since 2026-07

Both matter because `iroh_transport` holds the router and node identity in
**process globals**; anything sharing a process shares one node.

| Flow | Where |
|---|---|
| Drive reconciles across a real OS process boundary | `lib/tests/cross_process_sync.rs` |
| Iroh NodeID survives an unclean kill (`abort()`, no flush) | `lib/tests/identity_durability.rs` |
| Paired peer + its relay/direct addresses survive a kill | `lib/tests/identity_durability.rs` |
| Two whole servers pair via `POST /iroh-sync` and reconcile | `server/tests/it/iroh_pairing.rs` |
| `/iroh-sync` refuses malformed node ids with a UI-showable error | `server/tests/it/iroh_pairing.rs` |

### Glue

| Flow | Where | Note |
|---|---|---|
| Browser records a peer and calls `/iroh-sync` | `data-browser/src/helpers/pairing.test.ts` | stubbed fetch |
| Known-peer store: labels, dedupe, corrupt data, quota | `data-browser/src/helpers/knownPeers.test.ts` | |
| `forgetServerPeer` signs the exact `?node=` URL, and fails soft | `data-browser/src/helpers/managedServer.test.ts` | mocked `signRequest` |
| Opening a foreign HTTP drive does not move `serverUrl` | `browser/lib/src/store.set-drive.test.ts` | bare origin still switches the server; path-bearing HTTP is a drive |
| Canvas editing session merges a peer's stroke | `flutter/rust/src/api/simple/tests.rs` | |
| Whole-list rewrite (erase/undo) keeps a peer's stroke | `flutter/rust/src/api/simple/tests.rs` | |
| Bridge `start_peer` → `add_known_peer` → `peer_sync` pushes a drawing to a real remote process | `flutter/rust/src/api/simple/peer_tests.rs` | receiving side writes the receipt |
| Bridge known-peer bookkeeping (add / rename / dedupe / forget) | `flutter/rust/src/api/simple/peer_tests.rs` | |
| Bridge `peer_sync` to an unreachable node errors rather than hanging | `flutter/rust/src/api/simple/peer_tests.rs` | |
| **`POST /iroh-sync` request shape, both sides** | `testdata/pairing-request.json` + `pairing.test.ts` + `iroh_pairing.rs` | shared fixture binds them |
| Dart pairing-code parser, peer-sync result formatting | `flutter/test/atomic/` | pure parsers |
| Rotation does not treat a metrics-change pop as "back to gallery" | `flutter/test/canvas/rotation_pop_test.dart` | |
| `AtomicNode`: `mutate` on one node, `apply_commit(IngestPolicy::Peer)` on another, query + `DbEvent` reflect it | `lib/src/runtime/node.rs` | in-process, no transport; `LocalCache` skips signature check, `Peer` does not |

## Local full-text search

| Flow | Layer | Where |
|---|---|---|
| Exact title, prefix typeahead, 1-edit typo (`avacado`→`avocado`) | protocol | `lib/src/search/tests.rs` |
| Title ranks above description; parent/drive scope; Loro body text | protocol | `lib/src/search/tests.rs` |
| Update replaces old title; delete drops postings; commits skipped | protocol | `lib/src/search/tests.rs` |
| Tokenizer + prefix-Levenshtein | protocol | `lib/src/search/tokenize.rs`, `fuzzy.rs` |
| Query latency vs N (1k / 10k / 50k) | protocol | `lib/benches/search_bench.rs` (`--features db-redb`) |
| `Store.search` offline hits `ClientDb.search` | JS | `browser/lib/src/store.test.ts` |

Not covered: table `contains`; Playwright search overlay on the KV path; Flutter bridge `search`. Hosted `/search` is `atomic_lib::search` (Tantivy and MiniSearch are gone). Offline E2E polls `ClientDb.search`. Filters (`isA`, tags) are covered by `lib/src/search/tests.rs` and `server/tests/it/file_search_repro.rs`.

### Flow — the thin layer

| Flow | Where |
|---|---|
| Pairing code renders, is a routable envelope, carries no secret | `browser/e2e/tests/sync-devices.spec.ts` |
| Pasting a code: form gated to the app, malformed refused without dialling, node's refusal shown, success reports what synced, peer remembered | `browser/e2e/tests/pairing-dialog.spec.ts` |
| Paired-device cards render, expose a way to forget, and hide undialable entries | `browser/e2e/tests/pairing-dialog.spec.ts` |
| Copy pairing code | `sync-devices.spec.ts` |
| Add-a-device form validation | `sync-devices.spec.ts` |
| Sync page status renders | `browser/e2e/tests/sync.spec.ts` |
| Offline edits persist and sync on reconnect | `sync.spec.ts` |
| Second device cold-loads a drive from the server | `second-device-load.spec.ts` |

---

## Blind spots

### Plugin execution lifecycle (2026-09-05)

On `feat/plugin-model`, the JS plugin suite and Rust server plugin suite cover
caller-scoped get/query, verified drive binding, source pinning after edits,
review/source matching, no replay of pending/interrupted schedules, preservation
of query proposals, empty/partial checkpoint decisions, schema reuse and shared
TS/Rust manifest validation. `lib/src/db/plugin_schedule.rs` also decodes an old
MessagePack schedule containing an old approval. See
[plugin-model-review](planning/plugin-model-review.md) for limits and progress.

Remaining gaps:

- App/connection capability scope in addition to account authorization.
- Complete immutable release/installation lifecycle and permission upgrades.
- Remote write receipts, provider idempotency and uncertain-result recovery.
- Crash recovery of partially applied creates; current policy pauses for review.
- Durable event queue/backfill while a trigger's proposal waits for review.
- Egress streaming-cap and DNS pinning tests against a controlled HTTP provider.
- Connector convergence under normalization, concurrent edits and lost responses.

Ordered by how much they would hurt.

### 1. No cross-runtime peer test above the bridge

Canvas's *sync* is now covered against a real remote process
(`peer_tests.rs`), which is Canvas ↔ Desktop at the code level — both sides run
the same `atomic_lib` peer, and there is only one Iroh implementation, so the
wire protocol between any two surfaces is the same well-tested code.

What is still untested is everything **above** the bridge: the Dart call sites,
Flutter's lifecycle, the Tauri wrapper, and the browser driving a real node.
Android-specific behaviour (backgrounding, process death, 16 KB pages) has no
automated coverage at all and is still hand-verified on devices.

### 2. `peer_announce` and discovery from the bridge

`peer_announce` and `peer_discover_sync` remain untested — they depend on pkarr
relay reachability, which the bridge tests deliberately short-circuit by
handing addresses over directly. `pkarr_discovery_and_iroh_sync` covers
discovery in `atomic_lib`, but not through the bridge.

### 3. Remaining one-sided contracts

`POST /iroh-sync` is now bound by a shared fixture
(`testdata/pairing-request.json`): the browser test asserts it *sends* that
body, the server test asserts it *accepts* it, and renaming a field fails both.

`/forget-peer` is covered on both sides now — `iroh_pairing.rs` for the handler
(unsigned refused, full pair → listed → forget → gone lifecycle) and
`managedServer.test.ts` for the client (signs the exact `?node=` URL). They are
not *bound* by a shared fixture the way `/iroh-sync` is, so a rename would still
pass both; the query-parameter name is asserted literally in each.

Unbound: the `nodeId` property on `/server` as consumed by the browser — the
replacement for `/iroh-node-id`.

### 4. Tauri-gated UI

`ConnectToDeviceForm` (paste a code) and the pairing dialog are now covered —
`isRunningInTauri()` only checks for `window.__TAURI_INTERNALS__`, so
`page.addInitScript` reaching it is enough, and nothing on that path calls
`invoke`. See `pairing-dialog.spec.ts`.

Paired-peer cards are covered too, by seeding `atomic-peers` in an init script.

Still uncovered: `PairingLinkHandler`'s deep-link entry (the system camera
launching the app) and `IdentityReconcileGate`. Anything that genuinely calls
`invoke` needs a real desktop harness, not a faked global.

**Known wart, not a test gap:** `PairingLinkHandler` drops input that does not
start with `atomic://` or `did:ad:node:`, so pasting something that is not a
URI reports *nothing at all* — no dialog, no error. Only malformed input that
is URI-shaped reaches the flow and gets a message.

### 5. QR camera path

`scanPairingCode.ts` and the camera flow: untested at every layer.

### 6. Ephemeral / presence over Iroh

No producer or consumer exists (`EPHEMERAL` 0x40 is WS-only), so there is
nothing to test yet. Listed so it is not mistaken for covered.

### 7. Flutter integration_test is effectively dead

One 13-line smoke test, never run in CI — the pipeline has no emulator.

### 8. Known residual races

None outstanding. The concurrent-writer bug that lived here — a local edit
racing a peer update lost ~⅓ of all operations, because both paths
read-modify-write the same Loro snapshot and end in a replace — was fixed
2026-07-20 with a per-subject lock (`lib/src/subject_lock.rs`). Regression test:
`lib/tests/concurrent_commit_and_peer_apply.rs`, which lost 53–56 of 80
operations before the fix and now keeps all of them, with a sequential control
that isolates concurrency as the cause.

No known flaky tests. The one that was
(`rbsr_reduced_matches_full_sync_vv`) turned out to be a genuine RBSR bug, not
test noise — see below.

---

## Things that are *not* what they look like

Recorded because each one cost real debugging time.

- **`push_stroke` + `save_locally` cannot lose a peer's op.** The commit is
  imported into a freshly-read store doc and Loro import never removes ops. The
  damage from a stale editing session comes from *reads* — index-based deletes
  and whole-list rewrites — not from the append. A test written the obvious way
  passes with and without the fix.
- **A test child process must not drop its `Db`.** redb's `Database::drop`
  closes cleanly and makes pending `Durability::None` commits durable, so a
  durability test that lets the store drop is testing a graceful shutdown.
  `std::mem::forget` it before `abort()`.
- **Servers in one process share an Iroh node.** They all advertise the same
  node id regardless of whose store holds the data. Multi-server Iroh tests
  must use subprocesses, and the test process itself must run no server.
- **`--exact` filters need the module path** in the single-binary `it` suite
  (`iroh_pairing::child_runs_a_second_server`, not the bare name).
- **A leaked child server silently corrupts later runs.** Own it with a `Drop`
  guard so a panicking assertion still kills it.
- **The bridge's tests share one drive.** `DB` is a `OnceLock` and every test
  works in the same drive, so "find a canvas with strokes" matches a
  neighbour's drawing. Assert on a specific subject, and never change the
  active drive from a test.
- **Known peers are stored under a normalised node id**, not the
  `did:ad:node:` form the UI passes in. Look them up with
  `normalize_node_id`, or the lookup silently finds nothing.
- **A lock keyed only by subject couples unrelated stores.** `populate()` seeds
  well-known subjects that are byte-identical in every store, so a global
  registry makes two independent `Db` instances — including two tests sharing a
  process — wait on each other for no reason. `SubjectLocks` therefore lives on
  the `Db`, and every clone of a store shares one registry.
- **Measure a suspected regression on a quiet machine.** A test that looked
  newly flaky right after a four-minute stress run was passing 20/20 once the
  machine was idle. Compare against a stashed baseline under the same
  conditions before concluding you caused something.
- **A flaky test can be a real bug wearing a costume.**
  `rbsr_reduced_matches_full_sync_vv` failed ~1 run in 3. It was not noise:
  `reconcile_range` anchored its first child range at the first *local* key
  instead of the range's own `lo`, leaving `[lo, first_local)` covered by no
  child at all. A subject the remote had and we lacked, sorting below
  everything we held, was dropped from the diff and would never have synced.
  It looked intermittent only because the test's subjects are content-derived
  DIDs, so whether one landed in the dead zone varied per run — and
  `retries = 2` meant CI almost never showed it.

  The TypeScript port (`browser/lib/src/rbsr.ts`) had the **same** off-by-one,
  and it *is* live: `websockets.ts` uses it to compute the `subjects` filter a
  browser client sends the server, so an affected resource was never pulled.
  Both were fixed 2026-07-20, each with two deterministic regression tests.

  **Treat a flake as an unread bug report until proven otherwise** — and when
  an algorithm is ported, check the port for the same defect.

- **An empty local-DB collection page used to drop its aggregates.** Count=0
  is a real statistic (and sum=null is too). Leaving `collection.aggregates`
  unset made dashboard/table totals render an em-dash forever, because the
  follow-up `ResourceUpdated` never came — the rows were already in the JS
  store. Guard: `collection-empty-trust.test.ts`, plus the dashboard e2e
  that waits for `946.5` / `4` rather than the placeholder.

- **Opening a filled table (and the sidebar) flashed as if order changed.**
  Two independent paints: (1) WASM `parent=` queries are unsorted;
  hydrating each member notifies `ResourceUpdated`, and `useCollection`
  optimistic-added them in arrival order before client-side sort wrote
  the page. Guard: `collection-page-assemble.test.ts`. (2) The sidebar
  fetched children while `isA` was still empty, so every table row
  appeared in the tree until the class arrived and hid them. The
  ResourceSideBar now treats unknown class as hide-children. OPFS
  cold-load could also shuffle array props (`requires`/`recommends`) by
  seeding a new LoroList from JSON-AD then merging the snapshot;
  `importLoroUpdate(snapshot, true)` replaces instead. Guard:
  `resource.test.ts` ("importing a snapshot over a cache-seeded doc").

### Algorithms mirrored in two languages

`lib/src/sync/rbsr.rs` ↔ `browser/lib/src/rbsr.ts` are line-for-line ports and
must compute the same differing set on either end of the wire. Both carry the
same test names. A fix to one is a fix to the other; the golden-vector tests
(`item_fingerprint_matches_golden_vector`) pin the hashing, but the *traversal*
is only kept in step by mirroring the tests, so do that deliberately.

`lib/src/genesis.rs` ↔ `browser/lib/src/genesis.ts` also share a personal-drive
derivation (`personal_drive_subject` / `personalDriveSubject`). The cross-lang
vector (`personal_drive_cross_lang_vector`) pins the nonce, signature, and DID.

## Unified actions

| Flow | Layer | Where |
|---|---|---|
| ⌘K action section: prefix/keyword match, cap, `available`/`disabled`, no mid-word / resource-name hits | glue | `browser/data-browser/src/actions/matchActions.test.ts` |
| Shortcuts overlay / `/app/shortcuts` list equals `appActions` + `resourceActions` that carry a shortcut | glue | `browser/data-browser/src/actions/catalog.test.ts` |
| `asTool` verbs derive AI tools; `execute` calls `run` and respects `available` | glue | `browser/data-browser/src/actions/deriveTools.test.ts` |
| ⌘K shows a matching action and runs it; a resource-name query shows none | flow | `browser/e2e/tests/command-palette-actions.spec.ts` |
| `?` overlay lists registry shortcuts; `\` toggles the sidebar | flow | `browser/e2e/tests/shortcuts.spec.ts` |
| ⌘M searchable menu + ⌘↑ parent from the registry | flow | `browser/e2e/tests/resource-context-menu.spec.ts` |
| Parent action stays available on a non-drive stub and fetches parent at run | glue | `browser/data-browser/src/actions/resourceActions.parent.test.ts` |

Not covered: derived AI tools invoked through a real model; MCP protocol projection (no Atomic MCP server yet); collapsing specialized `destroy()` call sites (table rows, views, tags) onto the resource delete action.

## Documents

| Flow | Layer | Where |
|---|---|---|
| V1 element list + paragraph markdown (+ resource embed) → TipTap JSON; leftover Yjs `XmlFragment` walker; `{ type: 'ydoc' }` detection without loading `yjs` | glue | `browser/data-browser/src/views/Document/documentMigrationUtils.test.ts` |
| Opening a writable v1 document migrates it silently into the Loro editor (no "Update Document" button) | flow | `browser/e2e/tests/documents.spec.ts` |

Not covered: leftover Yjs-era DocumentV2 bodies end-to-end (needs a stored `{ type: 'ydoc' }` fixture); read-only v1 documents stay on the element list and have no e2e.

## Commits as envelopes

| Flow | Layer | Where |
|---|---|---|
| `LoroDoc` values are not KV-index keys | protocol | `lib/src/values.rs::loro_doc_is_not_indexed` |
| Content commits are not stored; genesis/ACL/destroy are | protocol | `lib/src/db/test.rs::content_commits_are_not_stored` |
| Sequential saves do not chain `previousCommit`; commit DIDs are not store resources | glue | `browser/lib/src/commit.test.ts` |

## Personal drive identity

| Flow | Where |
|---|---|
| Same agent key → same personal-drive DID | `lib/src/genesis.rs`, `browser/lib/src/genesis.test.ts` |
| Cross-language personal-drive vector | `genesis.rs` + `genesis.test.ts` |
| Repeat genesis for that DID merges Loro state | `lib/src/commit.rs::repeat_personal_drive_genesis_merges` |
| Repeat genesis without a cert is still rejected | `lib/src/commit.rs::repeat_genesis_without_cert_is_still_rejected` |
| `createDrive({ personal: true })` uses the derived DID | `browser/lib/src/store.personal-drive.test.ts` |
| Two stores with the same key mint the same subject | `store.personal-drive.test.ts` |
| Extra drives are listed on the derived personal drive | `store.personal-drive.test.ts` |
| Extra drive created offline drains on reconnect (genesis must not set a rewind baseline) | `browser/lib/src/offline-create-drain.test.ts` |
| Lists from a previous random-DID home are unioned onto the derived drive | `store.personal-drive.test.ts` |
| `Agent.personalDriveSubject` matches the genesis helper | `agent.test.ts` |
| `Db::setup` / `ensure_personal_drive` use the derived DID and are idempotent | `lib/src/db.rs::personal_drive_tests` |
| Extra `Db::create_drive` is listed on the personal drive | `lib/src/db.rs::personal_drive_tests` |

Not covered: Flutter `create_drive` still mints a random DID (the Rust
`ensure_personal_drive` helper exists for `setup()`). E2E sign-in on a second
machine with the old machine offline.

Cloud Vault display metadata: `vaultAutoBackup.test.ts` verifies name/emoji enrollment and refresh after edits; SaaS `enrollment_display_metadata_refreshes_and_survives_legacy_clients` verifies persistence and account ownership.

## Cloud Server setup

- `data-browser/src/helpers/managed/cloudSync.setup.test.ts`: missing placement,
  source-server replication and refusal, assigned-server connection ordering,
  and failed connection without local-drive promotion.
- `data-browser/src/helpers/managed/reconcile.test.ts`: pending/empty placements
  do not switch the app away from its source.
- Paired `atomic-saas/portal/e2e/server-setup.spec.ts`: setup opens the selected
  existing drive, never creates a content-free enrollment in the portal.
- Paired `atomic-saas/portal/e2e/server-hosting-live.spec.ts`: opt-in real sign-in,
  grant, signed enrollment, setup UI, source replication and destination HTTP
  read. Requires two isolated nodes and dev magic links (`ATOMIC_HOSTING_LIVE=1`).
  Verified with plain and managed destinations. `ATOMIC_HOSTING_MANAGED=1`
  additionally checks Active usage receipts and the switcher state. Production
  deployment and Desktop/Tauri replication are not runtime-tested.

- Hosting consent: `cloudSync.setup.test.ts` refuses transfer/enrollment without
  an explicit agreement; paired SaaS HTTP tests enforce and record version 1.
- `driveHostingState.test.ts` covers Local/Remote, empty placement, combined
  Server/Vault, disabled, paused and unknown states. Paired SaaS
  `drive-switcher-hosting.spec.ts` checks menu rendering and refresh/error
  behavior against mocked receipts in the running browser app.

- Billing return: `enrollment.test.ts` checks the typed 402 response; paired
  SaaS `server-billing-live.spec.ts` follows a free account through mock checkout,
  back to the selected drive, then explicit consent, replication and an
  authenticated read from the real managed node. Plan purchase alone creates
  no enrollment. Real Stripe-hosted test-card checkout remains a deployment check.

## Error reporting and feedback

- `browser/data-browser/src/helpers/feedback.test.ts`: unavailable reporting, failed delivery, blank input and successful submission.
- `browser/data-browser/src/helpers/sentry.test.ts`: runtime disable override, environment and build attribution.
- `browser/e2e/tests/feedback.spec.ts`: sidebar form, unavailable-reporting guidance, failed Sentry transport, retained input and successful retry; uses a fake Sentry project with intercepted transport.
- Real Sentry evidence and remaining production gates: `planning/sentry-feedback-readiness.md`.

### E2E browser diagnostic gate

Every spec imports the automatic fixture in `browser/e2e/tests/fixtures.ts`.
Unexpected console warnings/errors and uncaught exceptions fail; extra contexts
and tabs are included. `browser-diagnostics.spec.ts` verifies capture, exact
expectations and rejection behavior. See `planning/e2e-diagnostic-hygiene.md`
for current failures. This does not assert Rust process logs or Sentry delivery.

### Diagnostic root-cause follow-up (2026-09-07)

Strict probes cover feedback, sign-in, account changes, recovery and chat. Store
unit regressions cover loading personal-drive placeholders, database handoff,
render-time snapshot notification, and attachment creation before a form is saved.
WebSocket tests reject stale version-vector/reduced-sync responses after identity
or drive changes. Managed tests cover cancellation, eligibility, and confirmed
object collisions without a premature backup cursor advance. Concurrent local key
creation and sign-in use a persistence regression test.

See `planning/e2e-diagnostic-hygiene.md` and the SaaS
`planning/E2E_DIAGNOSTICS.md` for current acceptance totals and open release gates.

Additional regressions cover computed-filter membership invalidation, first-genesis
fork bodies, cancelled outbox writes, GET error classification, missing-base delta
recovery, and the known server-only browser capability fallback. Rust commit tests
count document-body changes in the causality guard while retaining rejection of
property writes that lose completely; expression tests exercise browser operator
aliases. The editor Link lifecycle test preserves telephone links across multiple
mounts without resetting or re-registering the global parser.

### Save durability and identity lifecycle regressions

- Client-library tests gate both the snapshot write and worker flush: an existing
  resource's save cannot resolve before either durability barrier completes.
- WebSocket tests deliver an old connection's close event after its replacement
  opens and verify the Store stays connected.
- HTTP and Loro-loader tests distinguish document-unload cancellation from an
  active-page failure; real failures remain visible.
- `initClientDb.handoff.test.ts` switches identities twice during the old worker's
  flush and verifies the obsolete intermediate database is never attached.
- Dashboard reload, offline tables, reconnect, search/deletion and generated
  Next.js/SvelteKit sites cover the corresponding browser flows.

The node-type toolbar lifecycle is covered by `NodeSelectMenu.test.tsx` (destroyed
editors do not expose state/commands) and `oxc-react-compiler.test.ts` (production
compilation does not hoist command getters into render). `sentry.test.ts` covers
packaged WebView initialization without server-injected Sentry configuration.

Automatic Vault scheduling (`vaultAutoBackup.test.ts`) covers sustained-edit
maximum delay, queued edits across drive switches, late account availability,
connectivity recovery, enrollment rediscovery after reload, and distinguishing
Tauri embedded nodes from remote servers. Native background execution after OS
suspension remains outside this scheduler's guarantees.
## Plugin release and recovery additions

| Flow | Layer | Where |
|---|---|---|
| Immutable package identity, corruption refusal, explicit public catalog | protocol | `lib/src/db/plugin_release.rs` |
| Local replay reuses created identities; uncertain receipt blocks duplication | glue | `server/src/plugins/apply.rs` |
| Duplicate external delivery and lost response after provider write | glue | `server/src/plugins/external.rs` |
| Independent edits, conflicting edits, tombstones, partial pages, acknowledged baseline | glue | `browser/lib/src/plugin-reconcile.test.ts` |
| Signed publication/write SDK refuses anonymous calls and never blindly retries | glue | `browser/lib/src/plugin-connection.test.ts` |
| Publish, discover, create independent draft | flow | `browser/e2e/tests/plugins.spec.ts` |

Not covered: real provider conformance, durable trigger edge backfill and upgrades.
Catalog badges remain unverified. Recovery and baseline coverage is listed below.

Plugin recovery follow-up (2026-09-06): `plugins/external.rs` tests confirmed-applied
recovery after a lost provider response, audit retention, evidence validation,
connection isolation and refusing receipt replacement. `plugins/connection_state.rs`
tests stale checkpoints, divergent projections, whole-page atomicity, identity
collisions, empty pages and tombstones. `plugin-connection.test.ts` covers recovery
SDK serialization and refusing automatic retry of a stale checkpoint. These are
host-contract tests; provider verification and a recovery UI remain uncovered.

## GitHub issues ↔ kanban pilot

`server/src/plugins/sync_session_tests.rs` runs the shipped provider bundle in
QuickJS/WASM against real Atomic persistence and a simulated GitHub host. It covers
imports, creations, independent/competing edits, kanban transitions, unrelated
labels, stale previews, uncertain-write refusal, approval identities and an
imported issue triggering a linked chatroom Message through the ordinary trigger
engine. `connection_state` tests cover idempotent checkpoint recovery.

`integrations/github-issues/adapter.test.ts` covers pagination, PR exclusion,
manifest scope, failed reads and bundle drift. `automation.test.ts` checks the
message-action template. `atomic.live.test.ts` is opt-in and installs the real
bundle/private release/kanban through an isolated HTTP server without GitHub calls.
`plugins.spec.ts` covers sidebar discovery, icons and browser sandbox approval.

Live GitHub conformance, durable event replay, concurrent-edit atomicity,
background sync and scale/performance are not covered. Dagger's Rust test feature
selection now includes the sandbox; the updated container gate has not been run.


### Background sync and independent JS automations (2026-09-06)

- `plugins/triggers.rs`: transactional event backlog while no listener runs or a
  review is pending, preserving a waiting event when auto-execution is enabled,
  and subprocess termination/reopen before notification delivery.
- `plugins/sync_worker.rs`: completed-review grant requirement, pinned background
  execution, no repeat on a quiet tick, and hard restart midway through a saved
  session without a browser or duplicate Atomic create.
- `plugins/sync_session_tests.rs`: hard termination after provider acceptance,
  uncertain-result refusal, verified-receipt recovery without resending, and
  discovery markers excluding initial backfill/local-origin issues.
- `plugins.spec.ts`: UI-only GitHub installation, code-first event wiring into an
  independent automation with explicit integration references, sync approvals and
  persisted background toggles. The background check closes the browser context
  and reads status independently until a new scheduled run completes.

Still not certified: live GitHub failure recovery, multi-provider remote-action workflows, guided
Atomic uncertain-write recovery, query-outbox performance/retention at scale and
the Dagger container gate. Queue storage prevents loss; it does not imply
cross-system exactly-once execution or automatic reconciliation of uncertain writes.

### Live connector query snapshots

`integrations/github-issues/atomic.live.test.ts` now reproduces repeated
server-authoritative membership reads after five sequential inserts. This caught
merging generated query snapshots as editable CRDT data; the connection reader
now replaces query snapshots. This opt-in HTTP regression needs only a local
AtomicServer, and performs no GitHub calls.

`integrations/github-issues/github.live.test.ts` passed against the actual private
`ontola/atomic-github-sync-sandbox` repository. Explicit opt-in only: verifies
bidirectional issues, kanban status/labels, creation from Atomic and background
discovery -> independent JavaScript Atomic notification. Closes synthetic issues
and pauses polling afterwards. This does not certify real-provider crash recovery,
large-repository performance, email/push or chat delivery.

### Notion connector pilot (2026-09-06)

- Live setup exposed missing UUID path matching. `uuid_paths_are_single_canonical_segments`
  covers constrained UUID authorization and rejection of path escapes; the Notion
  sandbox fixture now checks every simulated request against the real matcher
  using a manifest fixture verified against the TypeScript provider declaration.

- `integrations/notion/model.test.ts`: stable property IDs, sparse patches,
  null/false/zero, option identities, rich-text refusal, long-text chunks,
  preservation of provider-only view configuration and title/display-name conflicts.
- `integrations/notion/plugin.test.ts`: preview, schema changes, pagination loops,
  independent edits/conflicts, stale approvals and provider access/rate-limit errors.
- `integrations/notion/package.test.ts`: exact shipped bundle reproducibility and
  POST-read versus PATCH-write manifest classification.
- `integrations/notion/atomic.live.test.ts`: optional real local Atomic installer
  with simulated Notion metadata; native properties and view bindings. No Notion calls.
- `server/src/plugins/notion_sync_tests.rs`: shipped bundle in actual QuickJS/WASM,
  real Atomic plan/apply and connection journals; bidirectional rows, property
  renames, independent view name/column changes preserving widths, local remote
  creation and refusal to duplicate an uncertain accepted create.
- `plugins.spec.ts`: Notion UI identifier validation before credential writes;
  shared integration preview/background flow remains covered by its existing E2E.

Live manual coverage: restricted personal database setup, initial title import,
Atomic-to-Notion title edit and Notion-to-Atomic edit, verified in both UIs. The
first imported table needed a reload to show membership: refresh/invalidation gap.
Missing provider code is now rejected before setup mutations (package regression).

Not certified: broader live Notion APIs, Notion background discovery delivery, board edits
in a live workspace, formatted page content, incremental sync or view parity
outside the explicitly supported subset. Plain-text fidelity refusals and
compatibility notes are part of the pilot contract, not full import coverage.

### Named integration actions

- Rust `plugins::actions::tests`: actual GitHub JS/WASM preparation, strict inputs,
  actor checks, explicit automation reference/release pin, stable call IDs, stale
  and expired approval, successful and uncertain-write retry protection (fake provider).
- `browser/lib/src/integration-actions.test.ts` and `plugin-manifest.test.ts`:
  MCP adapter/shared signed API contract and bounded action schema validation.
- GitHub install Playwright flow: named action form and sandbox-backed preparation;
  approval transport stubbed so no live GitHub issue is created.
- `plugins::actions::tests`: persisted history, cancellation, fresh recovery evidence,
  source/actor/configuration-pinned grants, app-scoped access, revocation, manual
  preview refusing automatic writes, and the fresh-call rate limit.
- Trigger and scheduler `integration_approval_resumes_*` tests: saved waits,
  same-input replay, receipt reuse, one Atomic effect after approval (fake provider).
- `browser/data-browser/scripts/integration-mcp.test.mjs`: real SDK stdio handshake,
  signed loopback requests, no approval tool and refusal of remote plaintext origins.
- Extended GitHub browser flow: cancellation, granting/revoking action permissions,
  recovery inspection followed by explicit confirmation (provider responses stubbed).
- Open: live provider recovery, production load, history archival,
  remote HTTP/OAuth MCP deployment and provider-specific automatic matching.

History pagination regression: `plugins::actions::tests::history_pages_migrate_ties_and_isolate_actors_under_load`
seeds 2,001 action records, migrates legacy rows, traverses tied timestamps,
inserts during traversal, rejects invalid cursors/page limits and excludes another
actor's records. It also verifies that expired history does not enter the pending
approval list. Browser `plugins.spec.ts` checks Load more and recovery together;
`integration-actions.test.ts` checks signed pagination requests. Production load
and worst-case automation-retention load remain untested.

Manual action retention: `compaction_preserves_ids_and_skips_provider_and_automation_records`
covers non-mutating preview, payload reduction, idempotent application, refusal of
archived IDs and approvals, and preservation of recent/manual provider attempts
and automation-originated records. The JS signed API test verifies preview defaults;
`plugins.spec.ts` checks that preview sends no cleanup mutation and the archive
button explicitly applies it (synthetic cleanup response). Physical database
shrinkage and compaction of consumed automation receipts are not covered.

Completed manual retention:
`completed_manual_retention_preserves_journal_tombstones_and_recent_recovery`
verifies explicit opt-in, 30-day settlement age, preservation of unknown-age/failed/
automation receipts, removal of duplicate recovery payloads, per-action counts,
idempotent cleanup, and refusal of direct executor retries against archived IDs.
The cleanup browser regression checks the real signed preview endpoint on a fresh
connection, then the opt-in request and explicit application using a synthetic batch.
Production retention/load measurements remain open; this test does not establish a safe deletion policy for automation receipts.

Completed automation acknowledgement: scheduler and trigger tests named
`finished_*_acknowledges_without_replaying_or_reading_old_waits` first execute a
successful run, then restore an interrupted schedule/queued event with unusable
integration waits. Fresh worker passes acknowledge the terminal run, preserve its
completion marker and create no second effect. These simulate the persisted crash
window; they do not kill a process at that exact instruction. Concurrent consumer/cleanup lock-race stress testing remains open.

Automation receipt ownership:
`automation_retention_waits_for_every_consumer_and_preserves_untracked_calls`
checks multiple consumers, completion age, a new active consumer preventing
cleanup, finished-run refusal, old-client opt-out and permanently protected
untracked access. Runtime test
`only_host_triggered_runs_own_receipts_and_js_cannot_change_the_identity`
checks public trigger spoofing and mutation of the trusted trigger ID in JS.
The cleanup UI passes explicit automation opt-in through the signed endpoint.
Worst-case consumer-count load and abandoned-consumer reconciliation remain open.

Consumer abandonment: `abandoning_a_consumer_is_audited_busy_safe_and_preserves_uncertainty`
checks busy-worker refusal, unrelated IDs, wrong actor, required reason, immutable
audit, refusal of future plan/receipt use, a fresh retention period, no approval
when all consumers were abandoned, and preservation of uncertain provider status.
Scheduler/trigger `abandoned_*_is_acknowledged_without_applying_its_saved_plan`
tests cover terminal acknowledgement without writes. The browser uses synthetic
consumer responses to check inspection, required reason and one explicit abandon
request; the JS client test checks the signed request fields. Deleted-automation
reconciliation and per-run (rather than per-worker) concurrency remain open.

Notion setup UX: `plugins.spec.ts` now covers empty-form feedback (previously
silently disabled), invalid identifiers before credential storage, Enter submission
and a mocked credential-storage rejection with a visible error and retry enabled.
OAuth and named database discovery now have coverage described below; live provider verification remains open.

Notion OAuth: `handlers::integration_oauth::tests` covers state ownership,
expiry and consumption plus connection ownership and sanitized database choices.
`notionAuth.test.ts` checks popup origin/source/state and cancellation cleanup.
`db::plugin_secret::store_tests` covers shared reference rotation/revocation,
origin/drive restrictions and legacy positional MessagePack decoding. Browser
`Notion OAuth selects a database by name and reports revoked access` uses mocked
provider authorization/discovery (not live Notion). Live OAuth and automatic
refresh remain unverified/unimplemented respectively.

Shared OAuth handoff: `oauth::handoff::tests` tests ownership across server,
agent, drive, provider and attempt, wrong retrieval proof, pending polling,
single-use delivery, concurrent redemption, duplicate completion, expiry,
credential removal and cleanup pagination past active entries. Service HTTP transport/authentication now has the tests described below.
Production TLS deployment and live provider exchanges remain unverified.

OAuth HTTP transport: `oauth::service::tests` covers missing credentials,
body-forged server identity, cross-server redemption, callback cancellation and
replay, bounded per-host admission, URL validation and a real loopback HTTP
client/service round trip. `notionAuth.test.ts` covers managed local polling and
abort. Playwright runs the same Notion setup fixture in direct and managed modes,
through native mapping creation, plus the manual fallback. These are authored
provider responses; production TLS/proxy configuration, real Notion consent,
refresh, immediate remote cancellation and SaaS deployment remain unverified.

Integration UX walkthrough (2026-09-07): desktop browser checked discovery and
connection dialogs. Four focused `plugins.spec.ts` cases pass, including the
Notion “Continue to sync setup” transition and GitHub automation creation.
Provider calls are fixtures; this does not verify live account authorization.

`discoverIntegrations.test.ts` checks assistant capability search, exclusion of
nonconnection drafts, partial failures and drives without a plugin schema.
It does not validate model tool selection or live provider credential health.

Assistant event previews: `previewTrigger.test.ts` checks event identity, payload,
clock validation and manual fallback. The existing Rust runtime authority test
was rerun successfully. New in-chat proposal controls use host refetch and existing
approve/cancel endpoints; browser interaction and live-model behavior are not yet covered.

Task schema/template pilot: `tableTemplates.test.ts` checks shared references
across Issue Tracker and Project Tasks. `task-schema.test.ts` checks the embedded
vocabulary against exported identities/options. `client-proxy.test.ts` checks
identity-preserving local schema resolution and rejects an unrelated proxy
identity. `plugins.spec.ts` adds GitHub setup into an existing Project Tasks
table, shared property identities, and preservation of its views. This verifies
setup, not live provider reconciliation against existing task records.
# GitHub token setup shortcut

The connection form now links to GitHub's fine-grained token template with
Issues write access and the owner from a valid owner/repository input. Catalog
extraction was checked; live GitHub token generation has not been tested.

New automation and integration shortcuts open a fresh assistant chat with resource
context, requesting user intent before draft creation. Browser acceptance of
these entry points and assistant-led creation remains open.

## MT940 bank statement importer

`integrations/mt940/parser.test.ts` has nine scenarios covering signed exact
amounts, reversals, balance reconciliation, invalid/truncated input, multiple
accounts, date rollover, multiline descriptions, nesting, reimport/conflict
handling, reference-free overlap, identical legitimate rows and resource bounds.
JSON-shaped narratives are rejected until legacy text materialization is fixed.
`plugins::bank_statement_tests::bank_statement_proposes_exact_nested_transactions`
runs the shipped JS in real QuickJS/WASM and verifies balance failures and
network-free proposals. Offline certification passes and is recorded in the
integration store's bundle-matched evidence.

`browser/e2e/tests/mt940.spec.ts` uses a synthetic statement with the real Worker,
server runtime, planner and signed persistence. It verifies invalid-file errors,
preview/apply, visible transaction amounts, reopening the installed importer,
and zero-change reimport. `/tmp/mt940-table.png` is the reviewed table screenshot.
No real bunq bank data has been tested. Installation recovery and exact-decimal
table aggregation remain uncovered. Shared identity concurrency is tested below.

## Shared import identity and source baselines

`browser/lib/src/import-records.test.ts` covers native localId persistence,
immediate-parent identity scope, ambiguous duplicates, local/source conflicts,
append-only source changes, existing links, interrupted batch replanning and
legacy adoption. `plugin-apply.test.ts` also verifies distinct approval markers
without modifying the reviewed proposal. The Clockify Store integration test
uses real typed resources, Loro commits and DID link rewriting with mocked HTTP.

`lib::import_identity::tests` covers these real-Db scenarios: concurrent signed identity
claims have one winner (the same ID in another destination succeeds), and stale
baselines/duplicate approvals cannot overwrite newer source values or local edits.
The existing `did_import_resolves_forward_local_id_references` regression confirms
JSON-AD nested references and reimport retain their subtree namespace.

MT940 and Clockify pass offline provider certification (27 fixture tests plus
their real QuickJS/WASM tests). Three Chromium flows pass against the rebuilt
local server: MT940 validation/import/reimport, Clockify setup/transport errors,
and Clockify linked import/reimport and parent migration. No live provider writes.

Remaining: offline-peer identity collision repair and whole-batch atomicity.
Process-abort recovery, lost-receipt recovery and browser conflict review
are covered by the follow-up checks below.

### Import follow-up acceptance

- Shared mapper/verdict/apply/Clockify Store suite: 54 tests pass. The Store test
  now injects a lost receipt after durable creation, then replans and applies only
  the missing two records. This is failure injection, not an OS-process kill.
- Core identity suite: three real-Db tests, including reviewed local-value
  preservation and stale-resolution rejection.
- Installer/Clockify update helpers: three tests for recovery after a lost receipt,
  failed-query refusal, JSON-only settings extraction and replacement generation.
- Browser: MT940 and both Clockify flows pass. The linked Clockify flow now also
  exercises both conflict choices, clean repreview, and a reviewed installed-code
  update that restores the bundled source without changing its settings.
- All four provider certifications pass (50 offline fixtures; four live cases
  skipped intentionally). GitHub and Notion real-runtime tests additionally assert
  persisted provider-qualified native localIds while retaining two-way behavior.
- `lib/tests/import_durability.rs` aborts a child process after an acknowledged
  DID import, reopens redb and verifies identity lookup plus continued nested writes.
  Removing the commit flush reproduces loss; restoring it passes.
- Schema unit tests recover unattached saved terms. The resumable-installation
  helper reuses saved logical steps while preserving repeated identical rows.
  `installation-recovery.spec.ts` injects a lost table-class receipt and checks
  that retries reuse the class, table and view.
- Duplicate-review fixture covers record links and blocked Apply; it does not
  simulate replication between independent nodes.
- Still unfinished: cross-node collision repair, universal adoption of resumable
  setup, and live account upgrades.

### Recovery verification (2026-09-07)

Five Chromium flows pass against rebuilt native/WASM code: interrupted table
installation, duplicate-source review, MT940 import/reimport, Clockify setup
errors and Clockify linked import/conflict/upgrade. Both changed providers pass
full offline certification. Frontend typecheck and client declaration build pass.
The three core identity tests pass, with the stale-baseline regression repeated
15 times to exercise concurrent Loro ordering. These checks make no live provider
writes and do not demonstrate offline collision repair.

### Offline duplicate preservation

`import_identity::tests::offline_duplicates_remain_visible_after_sync_in_both_orders`
creates the same source identity independently in two databases. Bulk SYNC_PUSH
and live UPDATE each preserve both DID resources and their distinct names in
both arrival orders and on replay. Lookup reports ambiguity and a third authored
import is rejected. This exercises the real persistence/index path, but not
network transport, OS-process isolation or reviewed alias/reference repair.

### Reviewed primary-record decisions (2026-09-07)

- Native identity regression now saves a signed decision, rejects a stale member
  snapshot, keeps both original values, survives replay, and reopens review on a
  new offline edit. Both bulk/live arrival orders remain covered.
- `import-resolution.test.ts` covers ordering, primary updates, retained-copy
  changes, missing/unseen members and competing decisions followed by re-review.
  The mapper test verifies subsequent proposals target only the reviewed primary.
- Connection-state test verifies alias provenance, preserved baseline, incremented
  revision, idempotent reads and rejection of the earlier checkpoint revision.
- `drain-datatype-tags.test.ts` reproduces and fixes newly added JSON values becoming
  strings on incremental saves. The full client suite has 564 passing tests.
- Five Chromium flows pass against rebuilt native/WASM code. Duplicate review uses
  real authenticated SYNC_PUSH plus a signed primary decision and fresh lookup;
  the other flows cover setup recovery, MT940 and Clockify. It does not yet test
  field consolidation, graph-wide relinking or independent OS-process resolution.
- Frontend typecheck and client declaration build pass. Clockify and MT940 offline
  certifications pass; no live provider writes were made by these tests.

### Reviewed field consolidation

`import-resolution.test.ts` covers explicit choices, absent fields, protected
fields and unknown members. The native offline-duplicate regression now rejects
an unfulfilled choice and persists the reviewed field value while preserving
the retained record, through both replica ingress paths and arrival orders.
`import-reference-review.test.ts` covers typed links, preserved array order and
multiplicity, skipped history/text/JSON, lost acknowledgements, stale records and
idempotent retry after partial completion. The native signed-commit test verifies
that a stale link update cannot overwrite a newer value, while normal edits can
retain the review receipt. Five native identity tests pass.

The Chromium duplicate-review flow now also selects a value from the other copy,
saves it to the primary, discovers a typed incoming link, applies it and verifies
that refreshing finds no remaining supported links. Broader graph-wide discovery,
all-or-nothing multi-record transactions and actual network partitions remain
outside this coverage.

The extended link-review browser flow also edits a second record after preview:
its link stays unchanged, the other record is confirmed, and reopening the primary
page resumes discovery without duplicating completed writes. Five focused browser
flows passed across the final runs (setup recovery, duplicate review, MT940 and
Clockify), with 567 client tests, native checks and offline certifications passing.

### Searchable creation catalog (2026-09-08)

`new-resource-catalog.spec.ts` verifies searchable table and website templates in
folders, selection passed to table setup, server-confirmed nesting for table and
website imports (both parent URL parameters), and the minimal assistant prompt
on a 390px viewport. It checks that the request remains editable when a model
needs connecting; it does not send a live model request. The blank-table setup
regression also passes. `creationCatalog.test.ts` covers catalog completeness,
multiword search and the assistant parent context. Frontend typecheck passes.

## Integration workspace tabs (2026-09-08)

`browser/e2e/tests/integration-workspace.spec.ts` installs a GitHub connection
without provider credentials and verifies its kanban opens by default, source and
secrets are hidden until their tabs are selected, automation creation is available,
and a changed opening-view setting survives reload. Uses the existing table view
renderer and table-default-view property. Typecheck passes. No live provider sync
or standalone custom AppFrame behavior is exercised by this test.

The integration workspace browser check also visits all management tabs and
verifies Edit with AI opens the assistant with an editing request. Screenshots
were inspected for tab spacing. This verifies handoff, not live model edits.

The integration workspace test holds the preview HTTP response to verify the
spinner, busy label and disabled button, then returns a provider error and checks
that the error is visible and preview can be retried. No live provider request is
made for this failure-path check.

## Paged table hydration count (2026-09-08)

`collection-page-assemble.test.ts` reproduces 90 rows becoming 150 when deferred
hydration notifications re-add rows outside page zero. Covers full-query membership
and reconciling optimistic additions already represented in that query. The other
collection sorting, drive-scope and empty-result regressions are run alongside it.
Verified in the user's Zen integration table: total is 90, final rows render, and
the phantom loading rows are gone. No source issue records were edited.
