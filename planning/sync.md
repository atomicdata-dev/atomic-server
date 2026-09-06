# WebSocket sync — commits and subscriptions

> **Status:** Shipped, as-built. Persisted commits over WS (protocol, server, browser), unified `UPDATE` / `DESTROY` with `QUERY_UPDATE` and later `SUBSCRIBE_QUERY` removed, drive-scoped fan-out, the Flutter WS session. The last test gaps (`ws_errors.rs`, `ws_unsub.rs`, browser `WSClient.postCommit()`) closed 2026-09-04.

> **Broader direction:** Multi-device and multi-transport sync is described in
> [`unified-sync.md`](./unified-sync.md) (one API, WS or Iroh; mobile should match
> browser live queries, not manual `peer_sync`).

## Status

**Persisted commits over WS** — implemented (protocol, server, browser). See
[Rollout](#rollout) below.

**Closed 2026-09-04:** `ws_errors.rs`, the `UNSUB` test (`ws_unsub.rs`,
2026-09-03) and the dedicated browser `WSClient.postCommit()` tests
(`websockets.test.ts`) all landed. See [Test coverage gaps](#test-coverage-gaps).
*Flutter on WS session* was listed here as open on 2026-05-28 but had already
shipped (`flutter/rust/src/api/simple/ws_sync.rs`, first in `dd771c293`
2026-05-21: authenticate, `SUB` the active drive, per-canvas subscribe); struck
2026-09-01.

**`QUERY_UPDATE` removed** — first narrowed in `dd771c29` (drive-wide only fired
on membership), then deleted entirely. Drive-wide subscribers now receive
creates/destroys via the same `UPDATE` / `DESTROY` channel that already
carried edits. The `SUBSCRIBE_QUERY` registration primitive outlived it by
three months and was removed 2026-09-04: no client outside the Rust
integration tests ever sent it. The lib's watched-query index stays.

**Drive-scoped fan-out** — the drive-wide fan-out now delivers a commit only to
subscribers of the resource's *owning* drive (via `Subject::is_within_drive` +
the genesis `drive` propval), not to every drive subscriber. This closes a
cross-tenant commit leak (and the e2e 401-spillover flake it caused). See
[`commit-fanout-drive-isolation.md`](./commit-fanout-drive-isolation.md).

---

## History / context

WS sync works well for browser + server + OPFS. Flutter canvas has used Iroh bulk
sync separately; that path is being replaced by the unified plan.

Outstanding product/UX issues (Iroh-era):

## Handshake and context

- We can pair with QR code, and the QR code transfers some information about the name of the device. But this only gives ONE of the devices information about the other device - only the QR scanner knows the name of the other
- The UX is odd. What if user A scans a QR of user B? That does not necessarily mean user B agrees that A should access this. I think this means we need to initialize a share request.
  - **Current (2026-07-17).** Answered in two halves. The pairing code is
    routing only ([`device-pairing.md`](./device-pairing.md), 2026-07-10), so
    scanning grants nothing by itself. Since `683a25d4a` (2026-07-17) a
    cross-user dial *passes* AUTH and B's node serves A only what A's agent
    may `check_read`, per subject; `KnownPeer` persistence is gated on who
    dialed. So "user B agrees" is expressed as rights on B's resources, not
    as a pairing decision — and the share request below is the primitive for
    *asking* for those rights, not for admitting the connection.
  - **Proposed primitive:** the constrained append-only inbox in
    [`authorization-sync.md` § Constrained append-only inbox](./authorization-sync.md#constrained-append-only-inbox-first-contact-and-bridges)
    is the share-request mechanism. A first-contact "knock" is appended
    to the target's inbox by the requesting agent; the target accepts
    or rejects through normal owner-side commits.

## Deletes over bulk sync

> Trust model (hub vs bulk, same-agent vs share): [`unified-sync.md` § Trust and authority](./unified-sync.md#trust-and-authority).

- **Live path (no protocol change):** signed destroy commit → `DESTROY (0x12)` on WS; Iroh live loop mirrors `DESTROY`.
- **Bulk path:** `SYNC_DIFF` JSON now includes `remove: string[]` so peers delete instead of re-uploading subjects that vanished from the other side's VV map. Documented in [`docs/src/websockets.md`](../docs/src/websockets.md).
- **Local tombstones:** `lib/src/sync/tombstones.rs` records destroys in `PluginMeta` so `handle_sync_vv` can emit `remove` and `import_sync_push` won't resurrect. Not on the wire.
- **Flutter:** every delete must call signed destroy + `try_push_commit` / `nudge_peers` (folder delete was UI-only; fixed like folder rename).

## Bugs

- After signing in with the same secret on 2 devices, and using QR to set up sync, the resources sync successfully initially. Awesome. But after that initial sync, i don't see new strokes appears. When i create a new resource, i do see a new (empty) item appearing, but not the strokes. Even after manual retry / refresh.
  - **Root cause (Flutter / Iroh):** `push_stroke` → `push_list_item` updates the in-memory Loro doc but not `CommitBuilder`, so `save_locally()` hit the no-op path (`has_changes() == false`). Strokes stayed in the tablet's `CANVAS_CACHE` only; no `apply_commit`, no `DbEvent` delta, no live Iroh push. New canvases worked because `create_resource` commits through a different path.
  - **Fix:** `Resource::sync_loro_changes_to_commit_builder()` (called from `save` / `save_locally`) exports a Loro delta when only the in-memory doc changed. Test: `resources::test::push_list_item_save_locally_persists_strokes`.

## Plan: Persist commits over WebSocket (implemented)

### Problem

Persisted browser edits currently go through HTTP `POST /commit`, while live
updates come back over WebSocket. Once the server applies the HTTP commit and
emits database events, it no longer knows which WebSocket connection caused the
change. The originating browser tab can therefore receive its own change back as
a live update.

Loro can safely import duplicate updates, but duplicate transport work is still
wasteful and can trigger redundant UI fetches. The realtime Loro channel already
does the right thing: `LoroSyncUpdate` carries the sender `Addr`, and
`CommitMonitor` broadcasts to every subscriber except the sender. Persisted
commits should use the same source-aware shape.

Do not suppress by agent. A single agent can be open in multiple tabs or devices;
those other connections should receive the update. Suppression must be by
originating WebSocket connection.

### Direction

Move browser-originated persisted commits onto the WebSocket transport while
keeping HTTP `/commit` as a compatibility and fallback path.

The client still builds and signs the same Atomic Commit object. The transport
changes; the commit model does not.

### Protocol Shape

Add two v2 binary tags:

| Tag | Name | Role | Payload |
| --- | --- | --- | --- |
| `0x13` | `COMMIT` | Init -> Resp | `[request_id: u16] [commit_json_utf8]` |
| `0x14` | `COMMIT_OK` | Resp -> Init | `[request_id: u16] [server_commit_json_utf8]` |

`commit_json_utf8` is the same signed commit JSON sent to HTTP `/commit` today.
Keeping JSON here avoids changing deterministic signing, commit parsing, or
`loroUpdate` encoding in the first implementation. A later protocol revision can
compact the payload if needed.

`ERROR (0x03)` with the same request id is the failure response.

### Server Code Paths

Factor the shared commit application logic out of
`server/src/handlers/commit.rs::post_commit` into a reusable helper. Both HTTP
and WS should call the same validation and apply path:

```rust
async fn apply_commit_json(
    appstate: &AppState,
    origin: &str,
    body: &str,
    source_id: Option<String>,
) -> AtomicServerResult<String>
```

The returned `String` is the server-created commit resource JSON-AD that HTTP
returns today and that WS should send as `COMMIT_OK`.

Touched server files:

- `server/src/handlers/commit.rs`: extract shared apply helper, keep `/commit`.
- `server/src/handlers/web_sockets.rs`: decode `COMMIT`, call helper, send
  `COMMIT_OK` or `ERROR`.
- `server/src/actor_messages.rs`: carry source identity on commit/query
  notifications.
- `server/src/commit_monitor.rs`: store subscriber source ids and skip same
  source during broadcast.
- `lib/src/commit.rs`: add `source_id` to `CommitOpts` and `CommitResponse`, or
  another equivalent internal carrier that reaches `handle_commit`.
- `lib/src/db.rs`: copy the source id into emitted `DbEvent`s.
- `lib/src/sync/protocol.rs`: add tags plus encode/decode helpers.

### Source Tracking

Each `WebSocketConnection` gets a generated `connection_id`. When it handles a
`COMMIT`, it passes that id into the shared commit helper. The id must flow into
the commit monitor through `CommitResponse` or `DbEvent`, because
`store.apply_commit()` calls `store.handle_commit()` internally.

Commit monitor subscription maps should store a small subscription record rather
than only `Addr<WebSocketConnection>`:

```rust
struct Subscription {
    addr: Addr<WebSocketConnection>,
    source_id: String,
}
```

Use this shape for:

- resource subscriptions
- drive-wide subscriptions
- filter query subscriptions

When broadcasting `UPDATE` or `DESTROY`, skip subscribers whose
`source_id` equals the event source id.

HTTP commits have no source id and continue to broadcast to all matching
subscribers.

### Browser Code Paths

Add `WSClient.postCommit(commit): Promise<Commit>` in
`browser/lib/src/websockets.ts`, using the same pending request pattern as
`fetch()`.

Update `Store.postCommit()` in `browser/lib/src/store.ts`:

1. Prefer WS commit when the server WebSocket is open/authenticated.
2. Fall back to the existing HTTP `Client.postCommit()` path if WS is unavailable
   or the commit cannot be sent.
3. Preserve existing commit log behavior: pending -> sent/failed, with
   `commitIdOf(created)` coming from `COMMIT_OK`.

`Resource.signChanges()` and `Resource.pushCommits()` should keep their current
responsibilities: sign, queue, apply local pre-push state, drain commits, apply
local ack state, and push blobs after commit ack.

Touched browser files:

- `browser/lib/src/ws-v2.ts`: add tags and encode/decode helpers.
- `browser/lib/src/websockets.ts`: add pending commit requests and `COMMIT_OK`
  handling.
- `browser/lib/src/store.ts`: prefer WS in `postCommit`, retain HTTP fallback.
- `browser/lib/src/client.ts`: keep HTTP post as fallback.
- `browser/lib/src/resource.ts`: likely no behavior change, but tests should
  cover that `pushCommits()` still works with WS ack.

### Query Semantics Follow-Up (superseded)

Originally proposed narrowing `QUERY_UPDATE` to membership-only events. That
narrowing shipped in `dd771c29`, then `QUERY_UPDATE` was retired entirely —
drive-wide subscribers now get creates / edits / destroys through the same
`UPDATE` / `DESTROY` channel as resource subscribers. `SUBSCRIBE_QUERY`
registration was removed 2026-09-04 (unused outside tests).

### Documentation

Update public protocol docs in `docs/src/websockets.md`:

- Add `COMMIT` and `COMMIT_OK` to the v2 tag table.
- Add a "Persisted Commits" section.
- Document that the responder suppresses persisted commit broadcasts to the
  originating WebSocket connection.
- Update the typical session flow to show:

```text
-> COMMIT [request_id] [commit_json]
<- COMMIT_OK [request_id] [server_commit_json]
<- UPDATE ...     # sent to other subscribers, not the origin connection
```

Planning notes can stay here; the wire reference belongs in `docs/`.

### Tests

Add or update tests at these levels:

- Rust protocol tests for `COMMIT` and `COMMIT_OK` encode/decode.
- Server WS integration:
  - client A sends commit over WS and receives `COMMIT_OK`
  - client A does not receive its own `UPDATE` / `QUERY_UPDATE`
  - client B, subscribed to the same resource/query, does receive the update
- Browser lib tests for `WSClient.postCommit()`:
  - resolves on matching `COMMIT_OK`
  - rejects on matching `ERROR`
  - ignores unrelated request ids
- Browser/store tests for fallback:
  - `Store.postCommit()` uses WS when available
  - HTTP fallback still works when WS is unavailable
- Existing HTTP commit tests must remain green.

## Test coverage gaps

> Audit pass 2026-05-28 against `docs/src/websockets.md` (canonical wire spec).
> Layers in play: codec unit (`lib/src/sync/protocol.rs` `#[cfg(test)]`),
> engine / lib e2e (`lib/src/sync/tests.rs`, `iroh_e2e.rs`), server integration
> (one binary: `server/tests/it/*.rs`), browser lib (`browser/lib/src/*.test.ts`),
> browser e2e (`browser/e2e/tests/sync.spec.ts`).
>
> **Updated 2026-09-03:** most of this list is closed — see the ticks below.

### Coverage matrix (load-bearing frames)

| Frame / flow              | Codec | Engine | Server-int | Browser-e2e |
|---------------------------|:-----:|:------:|:----------:|:-----------:|
| AUTH / AUTH_OK            | (JSON) | yes    | every test (overlap) | —           |
| ERROR                     | yes   | —      | implicit    | —           |
| GET (request)             | yes   | —      | **—**       | —           |
| UPDATE — `SNAPSHOT`       | yes   | yes    | yes         | yes         |
| UPDATE — `HAS_COMMIT_ID`  | yes   | —      | **—**       | —           |
| UPDATE — `PUSH`           | yes   | yes    | yes         | implicit    |
| DESTROY (standalone)      | —     | —      | yes (`ws_destroy`) | —    |
| COMMIT / COMMIT_OK        | yes   | —      | yes         | yes         |
| SUB                       | yes   | yes    | yes (×5)    | —           |
| UNSUB                     | **—** | **—**  | **—**       | —           |
| SYNC* + SYNC_PUSH chunking| yes (×3) | yes (×3) | yes (×2) | —           |
| BLOB_REQUEST / RESPONSE   | —     | yes    | yes         | —           |
| Drive-wide membership (UPDATE/DESTROY via SUB) | n/a | partial | `ws_drive_membership` (×1) | implicit |
| Drive-scoped fan-out isolation (no cross-tenant leak) | n/a | n/a | `ws_commit_isolation` (×1) | n/a |
| HELLO (Iroh-only)         | yes (×8) | happy-path only | n/a | —    |
| EPHEMERAL (0x40 binary)   | yes (×5) | yes (`iroh_e2e`) | **—**  | —   |

### Gaps to close

- [x] **`server/tests/it/ws_get.rs`** — client `GET`, assert response is `UPDATE`
  with `HAS_COMMIT_ID` set and `commit_id == resource.lastCommit`. Regression
  test for the canvas-genesis-save bug fix (shipped 2026-05-28).
- [x] **`server/tests/it/ws_destroy.rs`** — standalone `DESTROY` frame delivery
  to subscribers (`ws_destroy_broadcasts_to_subscriber`).
- [x] **`server/tests/it/ws_errors.rs`** (2026-09-04) — `ERROR` format,
  `request_id` echo and codes for a malformed frame, an unauthorized signer, a
  tampered signature (`INVALID_SIGNATURE (9)`), an unknown subject, and two
  refusals in flight. An invalid `previousCommit` is not covered: the hub does
  not validate it (`validate_previous_commit: false`, issue #412).
- [x] **`UNSUB`** (2026-09-03) — `server/tests/it/ws_unsub.rs`: subscribe,
  unsub, confirm no further `UPDATE` while a second subscriber keeps receiving.
- [x] **`EPHEMERAL (0x40)` binary tag** — live, not reserved: codec in
  `lib/src/sync/protocol.rs` (`ephemeral_frame_tests`, 5 tests) and an Iroh e2e
  (`iroh_e2e.rs` `e2e_presence_crosses_the_link_without_being_stored`). Server
  integration coverage is still missing.
- [x] **`WsClient.close()` now flips `serverConnected` synchronously**
  (fixed 2026-08-25, commit `8d13b67`). `close()` calls `reportConnected(false)`
  + `rejectAllPending` itself instead of waiting for the `close` event, which
  Chromium can delay or suppress once the transport is already blocked
  (`browser/lib/src/websockets.ts:457-468`). Found via the intermittent
  "offline edits sync to server when connection is restored" e2e in
  `browser/e2e/tests/sync.spec.ts`, long misread as environmental flake.

### Overlap to thin

- AUTH happy-path is exercised by every server integration test. One dedicated
  `server/tests/it/ws_auth.rs` should carry it (`ws_auth_gate.rs` covers the
  fail-closed half); the others can assume an authed session.
- `SYNC_PUSH` chunking semantics (LAST flag, multi-chunk drain) are repeated
  across codec + engine + integration. Keep the codec assertions; let the
  integration tests stop poking at chunking internals.
- HELLO has 8 codec tests for a 4-byte-header frame — collapse the
  empty-name / control-strip variants into a parameterized table.

### Status

- [x] Audit (this section) — 2026-05-28
- [x] `ws_get.rs` + canvas-genesis-save fix
- [x] `ws_destroy.rs`
- [x] `ws_errors.rs` (2026-09-04)
- [x] `UNSUB` test (2026-09-03)
- [x] EPHEMERAL decision — it is live (codec + Iroh e2e), not reserved
- [ ] Overlap trim (AUTH-handshake repetition, SYNC_PUSH chunking, HELLO codec tests)

### Rollout

- [x] Add protocol tags and helper functions.
- [x] Factor server commit apply logic without changing behavior.
- [x] Add WS `COMMIT` handling and `COMMIT_OK`.
- [x] Thread source ids through commit events and suppress same-source broadcasts.
- [x] Add browser `WSClient.postCommit()`.
- [x] Switch browser `Store.postCommit()` to prefer WS with HTTP fallback.
- [x] Update docs.
- [x] Server WS integration: `server/tests/it/ws_commit.rs` (COMMIT + subscriber UPDATE).
- [x] Run server integration (`sync`, `query_subscribe`, `ws_commit`) + browser lib vitest.
- [ ] Browser lib: dedicated `WSClient.postCommit()` COMMIT_OK / ERROR tests (still mocked in commit tests).
- [ ] E2E save flows (browser `test-e2e`).
