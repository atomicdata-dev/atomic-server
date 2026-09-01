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
email-to-drive acceptance still needs dedicated flow coverage.
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
unenrolled/local drives and shared drives confirmed directly by their node.
`sync-devices.spec.ts` renders a managed connection with zero data for the selected
drive, injects another drive's completed sync, and verifies that Cloud Server
stays off with its setup action visible.

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
---

## Collection query authorization

| Flow | Where |
|---|---|
| Destroyed children don't inflate `parent=` `totalMembers` | `lib/src/db/test.rs` `destroy_clears_parent_index_count` |
| In-page auth-denied members: `count` equals `subjects.len()` | `unauthorized_query_count_matches_subjects` |
| Public child after a private streak still fills the page | `unauthorized_query_skips_denials_to_fill_the_page` (20 private, then one public) |
| Auth-denied listing does not full-decode ancestors; each member is still shallow-fetched | `unauthorized_collection_query_bounds_fetch_counts` (call counts, not wall clock) |

Not covered: wall-clock on a large real store (the 21.7KB-parent form from
`planning/slow-collection-queries.md`); per-GET rights walks on the invite-code
panel (memo is per-query, not per-request).

---

## Commit delivery and the Loro save cursor

The client exports each commit as a delta starting at its save cursor
(`_loroVersionAtLastSave`). If the cursor ever sits past ops the server never
received, every later delta is un-importable server-side — and Loro parks such
ops as *pending* (VV unchanged, empty diff), which without a guard is
indistinguishable from an idempotent replay. This lost a real user's
`form-pages` write in 2026-08.

| Flow | Where |
|---|---|
| Server rejects a delta whose deps it never received (pending import), and accepts the full-range re-send | `lib/src/commit.rs::commit_with_pending_loro_deps_is_rejected` |
| Idempotent replay of an already-applied commit is still accepted | `lib/src/commit.rs::idempotent_commit_replay_is_accepted` |
| Drain reacts to the pending-deps rejection by clearing the cursor and re-sending a self-contained snapshot | `browser/lib/src/store.test.ts` ("recovers from a server pending-deps rejection…") |
| `clone()` / `merge(replaceLoroDocs)` carries the cursor VALUE, not the current doc version | `browser/lib/src/resource.test.ts` ("clone preserves the save cursor value…") |
| Imports/echoes don't advance the cursor past unsigned local edits | `browser/lib/src/resource.test.ts` ("importLoroUpdate does not advance…") |

Not covered: the OPFS-suppression window (edits live only in memory between
`markDirty` and a successful drain — an app kill in that window still loses
them, `store.ts` `addResource`'s `!hasPendingCommits` gate); WS `COMMIT_OK`
acks carrying no server-side apply confirmation beyond the echoed commit.

---

## Forms

| Flow | Where |
|---|---|
| FormCondition evaluator (visibility + hidden-field validation skip) | Shared fixtures `testdata/form-conditions.json` loaded by `server/src/forms.rs::condition_fixtures_match_ts` **and** `browser/form-renderer/src/conditions.test.ts`. A fix to one is a fix to the other. |
| Definition serializer inlines FormCondition resources as `{field, operator, value}` | `server/src/forms.rs::definition_inlines_field_conditions` |
| Form ontology populate (incl. FormCondition) | `lib/src/store.rs::populate_forms_ontology` |
| Publish → anonymous submit of a branching follow-up | `browser/e2e/tests/forms-submission.spec.ts` ("branching hides a follow-up unless its condition matches") |
| Extended question types: validation + coercion per type (phone/url shape, currency bounds, dropdown membership, likert/rating range, matrix rows/columns + completeness, table columns/types/row bounds, address subfields), and all-empty composites reading as unanswered | `server/src/forms.rs` (`phone_field_accepts_common_shapes_and_rejects_junk` … `all_empty_composites_count_as_unanswered`) |
| Extended types route onto the existing summary shapes (choice counts / histogram / answer sample) | `server/src/forms.rs::extended_types_reuse_the_existing_summary_shapes` |
| `picture-choice` option images: subjects rewritten into `/form/{id}/image?file=`, and that route refuses files the form doesn't reference | `server/src/forms.rs::rewrite_option_images_only_touches_option_image_subjects` + `server/src/tests.rs::form_submission_flow` (step 3d) |
| Choice options resolve from the mapped SelectProperty's `allowsOnly` Tags into inline `{value,label,color,emoji,image}` objects, in order, with unset keys omitted | `server/src/forms.rs::resolves_choice_options_from_the_mapped_propertys_tags` |
| Option membership fails closed: a question with no options allows nothing, and a *label* is not an answer (answers are option subjects) | `server/src/forms.rs::choice_options_are_empty_when_the_property_allows_nothing` + `browser/form-renderer/src/validation.test.ts` ("choice option membership") |
| Non-choice questions keep their options bag untouched by option resolution | `server/src/forms.rs::non_choice_fields_keep_their_options_bag` |
| A question can borrow another column's Tags (`optionsSource.property`) — the source's list wins over the question's own | `server/src/forms.rs::choice_options_can_mirror_another_columns_tags` |
| A question can offer a table's *rows* (`optionsSource.table`) — answers are row subjects, a row *label* is not an answer | `server/src/forms.rs::choice_options_can_be_the_rows_of_a_table` |
| An `optionsSource` pointing at a deleted Property/Table fails closed (empty list) rather than falling back to the question's own tags | `server/src/forms.rs::an_unresolvable_options_source_allows_nothing` |
| A row whose label column is empty is left out of the options instead of falling back to its `name` | `server/src/forms.rs::rows_the_label_column_is_empty_for_are_not_offered` |
| A freshly added choice question has *no* options (no placeholder Tag resources) | `browser/e2e/tests/forms.spec.ts` ("create a form, add every field type…", step 4) |
| Every choice type stores a `resourceArray` of option subjects, single-pick included | `server/src/forms.rs::dropdowns_enforce_option_membership` |
| Multi-pick selection bounds (`minSelected`/`maxSelected`): too few / too many rejected, membership checked first, an empty answer still reads as unanswered, unusable bounds ignored | `server/src/forms.rs::multi_picks_enforce_selection_bounds` + `browser/form-renderer/src/validation.test.ts` ("multi-select selection bounds") |
| A maximum set in the builder reaches the rendered form: the hint line, options disabled at the cap, re-enabled on untick | `browser/e2e/tests/forms.spec.ts` ("a multi-select respects the maximum set in the builder") |
| Renaming an option in the builder rewrites the label in place (options are Tags, not copied strings) | `browser/e2e/tests/forms.spec.ts` ("create a form, add every field type…", step 4) |
| Builder can add every question type and they survive a reload | `browser/e2e/tests/forms.spec.ts` ("create a form, add every field type…") |
| `phone` accepts both the renderer's E.164 output and loosely formatted national numbers, and rejects a half-typed one | `browser/form-renderer/src/validation.test.ts` + `server/src/forms.rs::phone_field_accepts_common_shapes_and_rejects_junk` |
| `country` stores an ISO 3166-1 code: the list is complete and named, names localize, and a country *name* is rejected | `browser/form-renderer/src/validation.test.ts` + `server/src/forms.rs::country_field_takes_an_iso_code_and_rejects_a_name` |
| `country` summaries count picked codes by popularity (no configured option list to zero-fill) | `server/src/forms.rs::country_counts_rank_by_popularity_then_code` |
| Builder → publish → anonymous submit → row, for one type per value shape (dropdown/rating/address) | `browser/e2e/tests/forms-submission.spec.ts` ("extended field types round-trip from builder to submission") |
| Page transitions: off until the builder's Animate-page-transitions switch is on, then the page leaves in the right direction and the arriving page fades in one element at a time — a choice question's options included, each taking the slot after its own question — and `prefers-reduced-motion` still skips both | `browser/e2e/tests/forms.spec.ts` ("page transitions animate once switched on") + `browser/form-renderer/src/pageTransition.test.ts` |
| Every element in the cascade gets its own delay, in order, and a long page compresses the step rather than capping it (a cap made later options arrive with the question below them) | `browser/e2e/tests/forms.spec.ts` ("page transitions animate once switched on", computed-delay checks) + `pageTransition.test.ts::enterEnvelopeMs` |
| The animation opt-in survives the definition round-trip (unset = no animation, `true` = animated) | `server/src/forms.rs::definition_can_enable_page_animations` + `definition_includes_styling` |
| Drafts: what gets stored (answered values only, with each answer's field type), and what is dropped on load — another version, an expired draft, a deleted or retyped question, a page index the form no longer reaches. Storage that is absent or refuses (private mode, quota, partitioned iframe) leaves the form working | `browser/form-renderer/src/draft.test.ts` |
| Drafts end to end: returning to a half-filled form opens the resume dialog over the seeded answers, Continue keeps them, Reset wipes them on screen *and* on disk, and submitting clears the draft so the next visitor on that browser gets a blank form | `browser/e2e/tests/forms-submission.spec.ts` ("an unfinished form is restored from the visitor's own device") |
| The drafts opt-out survives the definition round-trip (unset = drafts on and the key absent from the wire format, `false` = off) | `server/src/forms.rs::definition_can_disable_drafts` |

Not covered (extended types): the client-side mirror of the new validators in
`browser/form-renderer/src/validation.ts` is only unit-tested for `phone` (the
one rule that deliberately diverges — it is stricter than the server for E.164
values); every other type is tested on the Rust side only, and the two are
hand-mirrored, so they can drift (the
same known gap as `buildFormDefinition.ts` vs `build_form_definition`); the
option-image *picker* in `PictureChoiceOptions.tsx` (uploading or picking a file
for an option) is only exercised manually; `choice-matrix` / `table-input` /
`picture-choice` are rendered and validated but never submitted end-to-end in
e2e.

Not covered (options as resources): that a form's choice column is usable *as a
table column* — picking its tags in `SelectCell`, grouping a kanban by it — is
untested, even though making that work is the reason the mapped Property is a
real SelectProperty. `max` enforcement in `SelectCell` (how single-pick is
expressed) has no test either. Deleting an option that submissions already
reference folds those answers into the summary's "Other" bucket; that path is
reasoned about but not pinned by a test.

Not covered (options from another table): the whole builder side is manual —
`LinkOptionsDialog` (picking a table + column), the "linked to X" panel and
unlinking, and everything `applyOptionsSource` does to the mapped Property
(mirroring `allowsOnly`, switching to a relation column for row-sourced
questions, destroying the question's own orphaned Tags). The client mirror
`rowOptions`/`tagOptions` in `buildFormDefinition.ts` has no test either — the
same hand-mirroring drift as the rest of that file. `OPTIONS_ROW_LIMIT`
truncation (a table with more than 1,000 rows silently offering only the first
1,000, and rejecting a pick past the cap) is untested, and the preview
deliberately applies no cap at all.

Not covered (drafts): the debounce/flush wiring in `useFormDraft` — the
`pagehide` and `visibilitychange` flushes in particular — is only exercised
through the e2e (which waits for the debounced write rather than forcing a
flush); a tab closed mid-keystroke is reasoned about, not pinned. The
`saveDrafts` opt-out is tested at the definition layer but never toggled in
the builder UI, and multi-page draft resume (the stored `pageIndex`) is unit
tested only. The resume dialog is exercised through its buttons; dismissing it
with Escape (which maps to Continue) is not.

Not covered: builder UI for adding/removing conditions (the e2e walks it once as setup, not as its own assertion); page-level (not field-level) branching in e2e (unit fixtures cover it); add/delete-page write ordering in `PageTabBar` (both now `await` the form's `form-pages` save — add before selecting, delete before destroying — but no test pins that ordering).

---

## Files and image previews

| Flow | Where |
|---|---|
| Upload → blob stored → content-addressed download round-trip | `server/src/tests.rs::upload_download_test` |
| `/download/files/{hash}` answers with the File's real mimetype, not `application/octet-stream` | `server/src/tests.rs::upload_download_test` |
| An uploaded SVG actually decodes in the preview (local `blob:` URL **and** the server `downloadURL`) | `browser/e2e/tests/filePicker.spec.ts` ("uploaded SVG renders in the preview") |
| File picker lists files, filters by name, previews text | `browser/e2e/tests/filePicker.spec.ts` |
| Upload while offline, then reconnect | `browser/e2e/tests/file-upload-offline.spec.ts`, `browser/lib/tests/upload-offline-reconnect.integration.test.ts` |

Both halves of the SVG row guard the same class of bug and neither implies the
other: a `blob:` URL takes its Content-Type from the `Blob`'s `type`, the
network URL from the response header, and an `<img>` renders SVG only when that
type is exactly `image/svg+xml` (raster formats it will sniff; SVG it never
will). `user_blob_response` also sets `nosniff`, so an `application/octet-stream`
answer breaks *every* image type on the network path, not just SVG.

Not covered: that the network `downloadURL` path is what actually renders once
the local bytes are evicted — the e2e asserts the header directly rather than
clearing the ClientDb and re-rendering. No test pins the `?w=`/`?f=` rendition
route's refusal to process SVG (`is_image_bytes` rejects it); the app avoids
that route for SVG, but nothing enforces that it keeps doing so.
