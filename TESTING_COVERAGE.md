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

## Browser WebRTC transport (issue #1396)

`browser/lib/src/webrtc-transport.test.ts` covers frame fragmentation/order,
backpressure and cancellation, bounded queues, caller buffer ownership, malformed
input and close behavior. `browser/e2e/scripts/verify-webrtc.mjs` establishes real
WebRTC channels between isolated browser contexts in Chromium and Firefox and
checks bidirectional 1 MiB transfers and disconnects without an AtomicServer.
The harness is loaded through Playwright routing; ICE and data transfer are real.
`lib/src/sync/browser_peer.rs` tests authentication, replay, drive isolation,
unauthorized snapshot writes, forged commits and outgoing permission revocation.
`browser/e2e/scripts/verify-peer-sync.mjs` uses distinct agents, real signaling,
WebRTC and OPFS with HTTP data access disabled: initial sync, concurrent edits,
presence, attachments, offline reconciliation, reload and signed deletion.
`browser-peer-sync.test.ts` covers parallel negotiation, isolated retries,
departure, membership checks and the per-browser connection bound.
`verify-peer-mesh.mjs` uses eight distinct Chromium agents: full mesh, ninth-member
rejection, concurrent creations, group presence, attachment replication, creator
departure, offline reconciliation and signed deletion. Rust regressions cover
late snapshots and delayed pulls after deletion (unknown pulls still fail), and concurrent blob replies across independent edges.
`browserPeerSync.test.ts` checks that another member can mint an invitation for
the existing room without restarting its connection.
`verify-peer-ui.mjs` checks invitation creation and disconnect in the Sync page.
These scripts require built WASM and `ATOMIC_PEER_SIGNALING_URL` pointing to the
SaaS signaling handler; neither starts an AtomicServer data process. The UI script requires
a running app at its configured test URL. They are not wired into CI yet.
Still uncovered: two physical devices, forced TURN, full Firefox drive sync,
public deployment, and interactive rich-text editor/cursor acceptance.

## How to read this

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
| Rejected cross-drive sync entry leaves no snapshot; later valid import cannot inherit rejected properties | `engine.rs` (`rejected_sync_entry_does_not_persist_snapshot`) |
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
start with `atomic:` or `did:ad:node:`, so pasting something that is not a
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
| Idempotent offline saves clear only after a complete local snapshot matches the synced baseline | `browser/lib/src/offline-create-drain.test.ts`, `browser/e2e/tests/offline-create-then-online.spec.ts` |
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
- Paired `atomic-saas/portal/e2e/server-setup.spec.ts`: setup checks the selected
  drive's subscription before opening hosting in the app; it never creates a
  content-free enrollment in the portal.
- Paired `atomic-saas/portal/e2e/drive-billing-ux.spec.ts`: billing has no fake
  account-wide free plan, named drives survive selection/reload/Back, and a
  paid drive's price and quota do not leak into an unsubscribed drive.
- `data-browser/src/helpers/driveBillingUrl.test.ts`: Sync links preserve the
  exact drive and portal, or open the picker when no drive is selected.
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

- `client-db.test.ts` verifies that cold worker initialization does not steal
  its own Web Lock or emit a false ghost-leader warning.
- `store.private-drive.test.ts` verifies that linking a private drive on a
  nodeless origin preserves the local profile without fetching it from the SPA.


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
connectivity recovery, enrollment rediscovery after reload, account expiry during
encryption and in-flight requests, and distinguishing
Tauri embedded nodes from remote servers. Native background execution after OS
suspension remains outside this scheduler's guarantees.

## Collaboration profile onboarding

The `e2e.spec.ts` authorization/invite and chatroom journeys now complete the
full-name step for inviter and new invitee, retain the secret-backup step, and
verify subsequent shared access. The chatroom journey also checks the named
personal drive. Browser warnings/errors fail these tests, including localization
render warnings. The authorization journey also covers cropped avatar upload, metadata and image
download from the recipient account, and existing-agent acceptance. SaaS
`portal/e2e/invite-signup.spec.ts` covers a real invitation through email signup,
recovery-code backup, automatic acceptance, and workspace reload. It also restores
the existing identity in a second browser before accepting the invitation again.
The test injects the standalone node's managed/portal metadata and declines
automatic workspace-vault enrollment (no S3 service). Invitation, email login,
encrypted identity recovery, and workspace operations use real local services.
The invite journey also rejects transient duplicate acceptance buttons, opens the
avatar file picker from the person button, and checks Feedback in the secret
backup dialog. `onboarding-storage.spec.ts` injects a failed ClientDb initialization
and verifies that signup controls stay hidden while recovery advice and Feedback
remain available. `onboardingStorage.test.ts` covers initialization readiness,
failure, missing attachment, and timeout. Actual private-window storage policies
across browsers remain outside the injected-failure test.
`ollama-feedback.spec.ts` checks sidebar feedback hover, local Ollama discovery
only after expanding AI settings, one-click URL acceptance and persistence after
reload. Its default run stubs the model-list endpoint; `TEST_REAL_OLLAMA=1` ran
successfully against local Ollama on 2026-09-08. The shared setup-panel component
is not separately covered by this probe. The existing Vite-only Wuchale/React
key warning when expanding AI settings is explicitly expected; other console
errors remain failures.

`username-live.spec.ts` changes the owner's display name through user settings
while a different agent reads an existing chat message. It asserts the author
updates without a reload and verifies a second change after the reader reloads.
`websockets.test.ts` checks targeted profile SUB frames, subscription replay,
multiple-reader cleanup through both Store unsubscribe APIs, and retaining
ordinary document drive-wide fan-out. Profiles no longer depend on being inside
the reader's active drive to receive live updates.


### Per-drive Cloud Server display

`driveSyncStatus.test.ts` rejects another drive's sync timestamp and scopes
asynchronous hosting/usage results to the selected drive and server. It covers
unenrolled/local drives, unknown enrollment, and the requirement for both enrollment and remote data before claiming hosted service. Node synchronization remains a separate status.
`sync-devices.spec.ts` renders a managed connection with data but no enrollment,
injects another drive's completed sync, and verifies that Cloud Server does not
claim hosting. It checks unknown recovery wording, account refresh on window focus,
and missing translation markers. `saved-drives.spec.ts` checks that a portal Open
link selects the requested drive, consumes the drive parameter, and preserves
current-drive behavior for ordinary resource links.

- Managed Vault display metadata: `vaultAutoBackup.test.ts` now covers a drive
  present only in local storage, as well as rename/emoji refresh. Manual enable
  and automatic backup share `driveDisplayMetadata`; only name and emoji are sent.
- FOSS logout: `helpers/managed/session.test.ts` verifies that an installation
  with no configured control plane makes no SaaS logout request (the CI smoke
  test exposed a 405 at `/api/logout`).

## Desktop workspace discovery (2026-09-08)

`sync::discover::tests::inspection_checks_access_without_importing_or_pairing`
uses real Iroh endpoints with node-bound AUTH: an authorized identity sees a peer name without importing
the drive or pairing; a stranger is rejected. The local Tauri debug build connected
to staging's advertised Iroh node and received a no-readable-data response for its
test identity. Live drive and node PKARR signatures were verified separately.
This does not yet prove restoration of the user's private staging workspace.

## Recovery-code passkey enrollment

`browser/data-browser/src/helpers/managed/recovery-enrollment.test.ts` verifies code-only reveal without WebAuthn, preservation of ciphertext and existing wrappers when adding a passkey, unlocking with either passkey, and no writes on wrong-code, account-mismatch or cancelled registration. Tests use WebCrypto, Argon2id and a simulated authenticator; physical mobile PRF support remains a device acceptance check.

## Plugin UI sandbox and private assets

- `browser/e2e/tests/plugin.spec.ts`: private plugin assets load through signed parent requests; custom rendering and RPC still work.
- The bootstrap test opens the shell directly and verifies its server-enforced opaque origin, independently of iframe attributes.
- `signout-signin-data.spec.ts` uses fresh persistent profiles on macOS WebKit because ephemeral contexts reject OPFS; these remain browser tests, not native Tauri acceptance.

- `browser/lib/src/store.test.ts`: receiving an older resource preserves the merged value in both JSON and the persisted Loro snapshot; dashboard configuration reload exercises the real OPFS path.

Drive changes and reauthentication on an already-open WebSocket: `browser/lib/src/websockets.test.ts` verifies a fresh SYNC is sent without reconnecting, including local-only drive exclusion. This covers the Sync page remaining at Connecting after sign-in or drive switching; live staging acceptance remains separate.

### Pending fork banner

`PendingForks.test.tsx` rejects ordinary resources, proposals for another subject,
and loading candidates even if a query page lists them. `forks.spec.ts` checks
ordinary resources after reload and real proposals on their original resource.
The reported Safari query contamination is not reproduced locally: WebKit test
setup currently fails opening OPFS before it can create its dev drive.

### Managed admission retries and content-addressed image downloads

- `local-outbox.test.ts`: enrollment/quota refusals stop after bounded retries,
  retain dirty edits, and can be re-armed by a new edit; legacy messages and
  structured `SYNC_REJECTED` classification are covered.
- `store-commit-fallback.test.ts`: a WebSocket enrollment refusal is not
  duplicated over HTTP; a transport failure still falls back.
- Server `errors::admission_error_tests`: enrollment/quota refusals carry a
  blocking code and HTTP 403 rather than an internal-error response.
- Server `tests::content_addressed_image_download`: raw, WebP and AVIF downloads
  work for a blob with no File resource at its hash URL; missing hashes return
  404, and attachment/nosniff headers are retained for renditions.

Staging triage verified that the two reported hashes still returned HTTP 200
without resize parameters. Deployment acceptance must recheck their resized
URLs and confirm the rejected-write rate falls after clients update.

Automatic browser discovery: `browser/data-browser/src/helpers/browserPeerSync.test.ts` verifies deterministic per-drive rooms, automatic startup for locally snapshotted drives, duplicate prevention, and skipping unknown snapshots. `ATOMIC_PEER_AUTOMATIC=1` with `verify-peer-mesh.mjs` verifies eight browsers rediscover trusted local drives without saved invitations, then sync creations, presence, attachments, reconnects and deletion. Full app UI acceptance remains separate.

The WebSocket unit suite also covers a socket closing while an asynchronous version-vector probe is computed: no SYNC is sent on the closed connection. General UI tests stub public discovery with an empty room; the separate peer mesh acceptance script still exercises real signaling and authenticated sync.

## Account drive catalog

`helpers/managed/driveCatalog.test.ts` covers union/deduplication, removal precedence,
offline retry/cache isolation, and stale results after logout or account switching.
`e2e/tests/drive-catalog.spec.ts` renders an account-only drive without a local
saved pointer, publishes the local drive, and applies a removal after reconnect
(real app/node, mocked account API). Existing saved-drive tests remain separate.
SaaS handler tests cover authenticated additive registration, account isolation,
service-backed discovery and removal versus stale upload. Catalog entries confer
no access to resource content. A live cross-app deployment acceptance is separate.

## Unified account passkey

`helpers/managed/accountPasskey.test.ts` checks account-credential reuse, server-challenge registration, PRF-output exclusion from API payloads, cancellation and standalone fallback. `recovery-enrollment.test.ts` covers additive migration, old recovery-code preservation, failed upgrades, unsupported login credentials and duplicate-credential PRF-salt selection. These use simulated authenticators and real WebCrypto/Argon2id.

Paired SaaS `portal/e2e/recovery-passkey.spec.ts` uses Chromium virtual PRF authenticators with the real control plane to verify app enrollment followed by portal login using one credential, reuse of a portal-created credential, and account-settings migration without replacing ciphertext or old wrappers. Physical Safari/iCloud, Android/password-manager and native-shell behavior remain device acceptance checks.

## September 10 SaaS and browser invite regressions

- `browser/lib/src/browser-peer-invite.test.ts`: signed invitation validation, expiry, target and issuer checks, recipient proof, and additive permission grants.
- `browser/e2e/tests/browser-invite.spec.ts`: distinct signed-in identities join a local drive through the app without the server invite endpoint.
- `browser/e2e/scripts/verify-peer-sync.mjs` with `ATOMIC_PEER_INVITE=1`: invitation bootstrap and real WebRTC reconciliation with HTTP data access disabled.
- `browser/e2e/tests/recovery-option.spec.ts`: recovery availability in the managed welcome flow.
- Existing-drive migration to browser-only storage and fresh-account email onboarding through a peer invitation remain unverified.
