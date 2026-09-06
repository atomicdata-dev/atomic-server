# Unified sync — one API, WS or Iroh

> **Status:** Active plan. Slimmed 2026-09-03: the 2026-07-02 audit passes
> (F1–F12), the dead-code / drift / consolidation inventories, the trust-related
> engineering-debt list and the closed phase checklists now live in
> [`completed/unified-sync-audit-2026-07.md`](./completed/unified-sync-audit-2026-07.md).
> This doc keeps the direction and the open work.
>
> Builds on the WS `COMMIT` work in [`sync.md`](./sync.md), sign-at-drain in
> [`sign-at-drain.md`](./sign-at-drain.md), and the runtime boundary in
> [`atomic-lib-runtime.md`](./atomic-lib-runtime.md).
>
> **Decision (accepted 2026-09-01):** the node that owns the URL is trusted with
> plaintext; anything that only stores is blind. F1 (Layer 2 as an unsigned write
> path) is closed by the signed state root, not by provenance on every push
> ([`completed/trust-model-decision.md`](./completed/trust-model-decision.md)).

## Goal

One **transport-agnostic sync API** in `atomic_lib` that apps use the same way whether
the carrier is **WebSocket** (browser ↔ server, mobile ↔ server) or **Iroh** (optional
device-to-device). Callers subscribe to **node events** (including live queries); they
do not call `peer_sync()` after scanning a QR code.

```text
Flutter / browser UI
        │
        ▼
  AtomicNode / SyncSession          ← single API
  · subscribe(Subscription)
  · mutate → dirty bit → Outbox
  · sync_drive (optional full reconcile)
        │
        ▼
  Local Db (offline-first cache)
        │
   ┌────┴────┐
   ▼         ▼
WsTransport  IrohTransport  ReticulumTransport  ← send/recv same v2 frames
```

Wire format: [`docs/src/websockets.md`](../docs/src/websockets.md) (Atomic peer
protocol). Encoding lives in `lib/src/sync/protocol.rs`; semantics in
`lib/src/sync/engine.rs`. Reticulum transport planning lives in
[`reticulum-sync.md`](./reticulum-sync.md).

## Current state (2026-09-03)

| Piece | Browser | Flutter native |
| --- | --- | --- |
| Local store | OPFS (`ClientDb`) | redb (`Db` in FRB) |
| Outbox shape | **Dirty-bit + sign-at-drain** (`local-outbox.ts`) — one signed commit per subject per drain pass; genesis envelope + offline `baseVersion` are the only stored artifacts; identity-scoped localStorage | Partial (`try_push_commit` when session open); no durable dirty queue, no backoff/blocked states |
| Persist commits | **WS `COMMIT` preferred**, HTTP `/commit` fallback (`Store.sendCommit`) ✅ | WS `COMMIT` when session open; else local only |
| Live updates | WS `SUB` → `UPDATE`/`DESTROY` (QUERY_UPDATE retired) | WS session + `pollDbEvent` |
| Bulk reconcile | binary `SYNC` on reconnect (hash-first probe, then filtered to the differing subjects), after outbox drain, narrowed by an RBSR range exchange (`RBSR_FP`/`RBSR_ITEMS`, full-VV fallback); `SYNC_DIFF.remove` applied ✅ | Iroh `SYNC`/`SYNC_PUSH` (peer.rs) |
| Multi-device | Same account on same server | WS-first; QR + Iroh bulk as fallback |

Since the 2026-07-02 revision: `AUTH` is required before `SYNC`/`SYNC_PUSH` on
the Iroh accept path (fail closed, `ERROR AUTH_REQUIRED`), the Iroh handshake
binds `AUTH.requestedSubject` to `SYNC.drive`, `SYNC_PUSH` refusals are visible
as `ERROR SYNC_REJECTED` / `UNAUTHORIZED_READ`, `EPHEMERAL (0x40)` presence is
live over the peer link and bridged by the server, RBSR range exchange is on the
WS wire as the text frames `RBSR_FP` / `RBSR_ITEMS` (stateless, with a full-VV
fallback), and the engine owns `AUTH`/`GET`/commit ingest — only `SUB`/`UNSUB`
are still hand-rolled in the server handler. The full history of how each of
those landed is in
[`completed/unified-sync-audit-2026-07.md`](./completed/unified-sync-audit-2026-07.md).

**Correction to a common assumption:** the outbox does **not** POST over HTTP as its
primary path. `drainOutboxSubject` builds a `/commit` endpoint URL, but that URL is a
routing key — `Store.sendCommit` sends the commit as a WS `COMMIT (0x13)` frame whenever
the socket is open, and only falls back to HTTP when it isn't. What *is* still HTTP-era
is the shape around that call — see [Outbox modernization](#outbox-modernization) below.

## Remaining work (2026-09-04)

Every still-open sync item, from this doc and from the plans it coordinates.
`[x] (2026-09-03)` = landed in the sync-protocol hardening PR (#1352);
`[x] (2026-09-04)` = landed in the follow-up PR from the same branch. Items
that turned out to be already done, or blocked by a finding, say so inline.

### Security

- [x] (2026-09-03) — `AUTH` carries a max-age and the WS
  `AUTH.requestedSubject` is bound to the server origin, so a captured frame
  cannot be replayed or aimed at another node.
  ([`serverless-p2p.md`](./serverless-p2p.md))
- [x] (2026-09-03) — the RBSR probe (`RBSR_FP` / `RBSR_ITEMS`) answers
  only for subjects the asking agent may `check_read`.
  ([`drive-reconciliation.md`](./drive-reconciliation.md))
- [x] (2026-09-03) — signed destroy commits replace the naked `DESTROY`
  frame on the Iroh live link (OQ4).
  ([`serverless-p2p.md`](./serverless-p2p.md))
- [x] (2026-09-04) — challenge `AUTH` over WebSocket: the server's first
  frame is `CHALLENGE (0x42)` with a per-connection nonce, the client signs
  `{origin}#{nonce}`, and a proof answering another connection's nonce is
  refused. Nonce-less proofs stay accepted (`AuthChallenge::Issued`) so
  pre-2026-09 clients keep working; `AuthChallenge::Required` exists for a
  strict mode but has no server option yet. Iroh streams still use the
  timestamp-bounded proof. ([`serverless-p2p.md`](./serverless-p2p.md))
- [ ] Wire `AuthChallenge::Required` to a server option and turn it on once
  every client speaks `auth-nonce`; add a challenge to the Iroh handshake.
- [x] (2026-09-04) — subscriptions are re-bound when a connection's AUTH
  changes its identity: the commit monitor re-runs `check_read` for every
  subject / drive / filter registration the connection holds and drops the
  unreadable ones (`RebindAgent`). Loro sync and presence registrations are
  not re-evaluated yet (this doc).
- [x] (2026-09-05) — Bootstrap admission (OQ5): a drive this node has never
  stored is admitted only through `admit_unknown_drive`. `Public` never
  creates one (even on `OpenPolicy`); Owner enrolls only the owner;
  Open still admits an authenticated first-sync; allowlist grace is
  unchanged. The live-write `Err(_) => true` ACL skip is gone.
  ([`foss-public-host-mode.md`](./foss-public-host-mode.md),
  [`serverless-p2p.md`](./serverless-p2p.md))
- [x] (2026-09-04) — F6: the unchecked replica applier (`ws_apply`'s old
  `apply_commit_json`) turned out to be reachable only through the pre-v2
  `COMMIT` text frame, which no server sends. It is deleted, along with the
  frame's parser and `IngestPolicy::Replica`; the server's rights-checked
  `handlers::commit::apply_commit_json` is the only function of that name.
  ([`completed/unified-sync-audit-2026-07.md`](./completed/unified-sync-audit-2026-07.md))
- [ ] Retain authorization-critical commits and verify grant chains before
  cross-agent peer sync. ([`authorization-sync.md`](./authorization-sync.md))

### Protocol / wire

- [x] (2026-09-03) — capability advertisement on `AUTH_OK` / `HELLO`, so
  peers negotiate instead of guessing (this doc).
- [x] (2026-09-03) — `UNSUB` implemented end to end (this doc).
- [x] (2026-09-04) — pipelined `COMMIT` and slim `COMMIT_OK`. The server
  always matched acks by `request_id` (each apply is its own spawned
  future); what landed is the client side: the browser drains an ordering
  tier of the outbox concurrently with a barrier between tiers, the Rust
  `WsClient::post_commit` settles only on its own `request_id`
  (`WsMessage::Error` now carries `request_id` and `code`), and a client
  that lists `commit-ok-slim` in its `HELLO` gets `[request_id] [commit_id]`
  back (this doc, [`sign-at-drain.md`](./sign-at-drain.md)).
- [ ] Genesis + first delta in one pipelined pair. **Blocked on canonical
  commit ids (2026-09-04 finding):** the delta's `previousCommit` must name
  the genesis id the *server* minted, which on an HTTP-subject drive is
  `https://host/commits/<sig>` rather than the `did:ad:commit:<sig>` the
  client could derive locally. Make the server always mint `did:ad:commit:`
  first (this doc, [`sign-at-drain.md`](./sign-at-drain.md) § contract).
- [ ] Flag cleanups. **Re-scoped by the 2026-09-04 findings** in
  [`sign-at-drain.md`](./sign-at-drain.md) § protocol cleanups:
  `HAS_COMMIT_ID` cannot be unconditional while push-imported state has no
  commit id; `SYNC_OK` doubles as the `SYNC_PUSH` chunk ack and four Rust
  call sites depend on it; dropping `PUSH` is safe but worth little.
- [ ] Layer-2 provenance: `SYNC_PUSH` entries carry `lastCommit` (and the signed
  envelope where available); import verifies and records it (F1) (this doc).
  The interim step is now complete on both halves: the browser hides
  outbox-pending subjects from the version vector it sends *and* (2026-09-04)
  from the `SYNC_DIFF.pull` it answers and the RBSR subject list it offers.
- [ ] One canonical cross-impl VV fingerprint (TS ↔ Rust byte-identical) and an
  incrementally-maintained fingerprint tree — today's is O(range).
  **Partly moot (2026-09-04 finding):** the two hash algorithms are already
  byte-identical and pinned by a shared golden vector; what differs is the
  *input* set (the browser adds all-zero rows for VV-less resources and
  hides outbox-pending subjects, the server filters by `check_read`), so the
  hash-first probe rarely matches. The remaining work is the input contract
  and the incremental tree.
  ([`drive-reconciliation.md`](./drive-reconciliation.md))
- [ ] Signed drive state root carried in the reconcile.
  ([`drive-reconciliation.md`](./drive-reconciliation.md))
- [ ] Scope declaration on `SYNC` so a scoped device stops receiving full
  snapshots and blob bytes it never asked for.
  ([`partial-sync.md`](./partial-sync.md))

### Client (browser / Flutter)

- [x] (2026-09-03) — browser liveness deadline (this doc).
- [x] (2026-09-04, verified, no change needed) — mobile: all three
  destroy/delete paths (`destroy_resource_and_sync`, `delete_canvas` via it,
  `delete_stroke` via `save_and_push`) already call `try_push_commit` when
  the WS session is open. `destroy_resource_and_sync` does not call
  `peer::broadcast_live_update`; a destroy reaches live Iroh peers through
  the signed-destroy `COMMIT` the push loop forwards from `DbEvent::Destroyed`
  (this doc).
- [ ] M4 — no authentication against a pre-0.40 server; adopted drives read 401.
  ([`pairing-ux-field-test.md`](./completed/pairing-ux-field-test.md))
- [ ] M8 — desktop "your changes are saved locally" is false with the ClientDb
  off. ([`pairing-ux-field-test.md`](./completed/pairing-ux-field-test.md))
- [ ] M12 — presence across a peer link: the `EPHEMERAL` wire and the server
  bridge landed, the two-device verification has not.
  ([`pairing-ux-field-test.md`](./completed/pairing-ux-field-test.md),
  [`p2p-presence.md`](./p2p-presence.md))
- [ ] Extra-workspace inventory — pairing syncs the named drive; there is still
  no "ask the peer which drives you have".
  ([`device-pairing.md`](./device-pairing.md))
- [ ] Measure per-peer presence bandwidth; coalesce the latest blob per
  (scope, channel) if needed (OQ1). ([`p2p-presence.md`](./p2p-presence.md))

### Architecture

- [ ] Port `LocalOutbox` semantics (dirty bit, genesis envelope, `baseVersion`,
  backoff, blocked) into `atomic_lib` as the `AtomicNode` outbox — one
  implementation for browser-wasm and Flutter (this doc,
  [`serverless-p2p.md`](./serverless-p2p.md)).
- [x] (2026-09-05) — Engine owns `SUB` / `UNSUB`: parse + `check_read` live
  in `handle_frame_full`; the WS handler registers the connection with
  the commit monitor only when the engine admits the subscription.
  `LoroSyncBroadcaster` is folded into `CommitMonitor` (Loro ephemera +
  drive presence maps, one `UnsubscribeAll`).
  ([`serverless-p2p.md`](./serverless-p2p.md))
- [ ] The drain targets a transport / `SyncSession`, not an endpoint URL string
  (this doc).
- [~] (2026-09-05) — `AtomicTransport` trait + in-process `ChannelTransport`
  and `SyncSession::{handle, serve}` (responder loop over the engine).
  `IrohTransport` / `WsTransport` wrappers, outbox drain, and the FRB
  `open_sync_session` surface remain.
  ([`serverless-p2p.md`](./serverless-p2p.md))
- [ ] `trusted_hub` / `untrusted_peer` split in `ws_apply.rs`.
  ([`serverless-p2p.md`](./serverless-p2p.md))
- [x] (2026-09-04) — the pinned QUIC connection lives in the live-peer
  registry entry itself (`LivePeer.connection`), so it is released with the
  peer; `LIVE_CONNECTIONS` (an append-only `Vec` that pinned every connection
  ever dialed) is gone, and the registry is a `LazyLock` rather than a
  `Mutex<Option<_>>` initialised as a side effect (a peer registered before
  that ran used to be dropped silently).
- [x] (2026-09-04, partial) — the dead `sync_drive_with_peer` and the private
  `_forced` indirection are removed; `WsMessage::{Commit, Resource}` and the
  pre-v2 text-frame parsers are gone. Four `sync_drive_with_peer*` entry
  points remain (`_outcome`, `_if_needed`, `_using`, `_using_outcome`), two
  of them test harness; the real collapse is the `SyncSession` item below.
  ([`serverless-p2p.md`](./serverless-p2p.md))

### Tests

- [x] (2026-09-03) — TS ↔ Rust golden-frame conformance test (this doc).
- [x] (2026-09-03) — adversarial test: a naked `DESTROY` from an
  unprivileged peer destroys nothing.
  ([`serverless-p2p.md`](./serverless-p2p.md))
- [x] (2026-09-03) — replayed-`AUTH` test (this doc).
- [x] (2026-09-04) — `server/tests/it/ws_errors.rs`: `ERROR` format,
  `request_id` echo and codes for a malformed frame, an unauthorized signer,
  a tampered signature (new code `INVALID_SIGNATURE (9)`), an unknown
  subject, and two refusals in flight at once. An invalid `previousCommit`
  is *not* covered because the hub does not validate it
  (`validate_previous_commit: false`, issue #412).
  ([`sync.md`](./sync.md#test-coverage-gaps))
- [x] (2026-09-03, already landed) — the `UNSUB` test:
  `server/tests/it/ws_unsub.rs` subscribes, unsubscribes and confirms no
  further `UPDATE` while a second subscriber keeps receiving.
- [x] (2026-09-04) — `browser/lib/src/websockets.test.ts`: `WSClient`
  against a fake socket — HELLO on open, CHALLENGE-bound AUTH and the
  timestamp-only fallback, `postCommit` settled by a slim or a full
  `COMMIT_OK`, an `ERROR` settling only the commit it names, a malformed
  ack rejecting instead of hanging, and `SYNC_DIFF` skipping outbox-pending
  subjects. ([`sync.md`](./sync.md#rollout))
- [x] (already landed, checklist was stale) — the F2 regression exists as
  `ws_apply::resolve_update_drive_spoof_tests::existing_resource_ignores_spoofed_drive_in_payload`.
  Still open: the same case end to end over a `SYNC_PUSH`, whose importer
  (`engine::import_sync_push`) does not go through `resolve_update`.
- [ ] Flutter integration: tablet + phone against a test server (this doc).
- [ ] Adversarial stale-node RBSR test as the Phase 2 acceptance gate.
  ([`drive-reconciliation.md`](./drive-reconciliation.md))

### Docs

- [x] (2026-09-03) — `docs/src/websockets.md` rewritten from the code, so
  the wire reference matches what the codec actually does.
- [x] (2026-09-04) — the sign-at-drain commit-granularity contract is
  written down in [`sign-at-drain.md`](./sign-at-drain.md) § "Commit-granularity
  contract" (one incremental commit per subject per pass that reached the
  server, plus at most one genesis; tiered concurrency across subjects).

## Outbox modernization

The dirty-bit sign-at-drain core is the right design — keep it. What needs work is the
plumbing around it, which still carries HTTP-era shapes:

1. **Endpoint-keyed routing.** `drainOutboxSubject` constructs an HTTP URL per POST just
   so `sendCommit` can look up the matching WS. The drain should target a
   *SyncSession/transport*, not a URL string. This is also what the Rust `AtomicNode`
   API needs, so browser and mobile share one drain implementation.
2. **Sequential single-subject round trips.** The drain awaits one `COMMIT` →
   `COMMIT_OK` per subject, in order. A reconnect with 50 dirty subjects is 50
   sequential RTTs. Fix in two steps:
   - *Pipelining:* `COMMIT` frames already carry `request_id`; send the whole sorted
     batch (respecting the agents → drive → children ordering for genesis chains) and
     match acks out of order.
   - *Optional `COMMIT_BATCH` frame:* one frame carrying N signed commits, one ack with
     per-commit results. Only if pipelining measurably isn't enough.
3. **Fat `COMMIT_OK`.** The full server commit JSON comes back; the client only needs
   the commit id for `lastCommit`. Shrink to `[request_id] [commit_id]`
   (already listed in [`sign-at-drain.md`](./sign-at-drain.md) § protocol cleanups).
4. **Genesis + first-delta = two round trips.** A new resource POSTs its pre-signed
   genesis envelope, then signs and POSTs the accumulated delta separately. Allow the
   drain to send both in one pipelined pair (genesis first; server applies in order).
5. **Commit merging is already in — say so and bound it.** Sign-at-drain batches all
   Loro ops since the last successful drain into ONE commit per subject per pass
   (26 keystrokes ≠ 26 commits). What it does *not* do is merge across failed passes —
   it doesn't need to: a failed POST never advances the save cursor, so the next pass
   re-exports one bigger delta and signs one fresh commit. Document this as the
   contract; the commit *chain* granularity is "one commit per drain pass that reached
   the server", which is the right audit granularity.
6. **Rust/mobile parity.** Port `LocalOutbox` semantics (dirty bit, genesis envelope,
   `baseVersion`, backoff, blocked) into `atomic_lib` as the `AtomicNode` outbox so
   Flutter stops maintaining a partial reimplementation (`try_push_commit`).

## State-first wire: commit as provenance envelope

The instinct "sync should merge commits and just send single update statuses by
default" is where the protocol is already heading — make it explicit:

- **Server → client is state-first today.** Subscribers get one `UPDATE` frame carrying
  the subject's Loro state (snapshot or delta) + `commit_id` — not a commit-by-commit
  replay. Keep that. Finish the flag cleanups that cement it
  ([`sign-at-drain.md`](./sign-at-drain.md)): `HAS_COMMIT_ID` always set, drop `PUSH`
  (redundant with `request_id == 0`), collapse `SYNC_OK` into an empty `SYNC_DIFF`.
- **Client → server: state accumulates locally, ONE signed commit per subject certifies
  it at drain time.** The commit is not the unit of editing; it's the signed envelope
  that authorizes a state transition. This is the sign-at-drain model and the
  `retention` direction in
  [`commit-retention-and-state-certificates.md`](./commit-retention-and-state-certificates.md).
- **Layer 2 carries provenance instead of competing (fixes F1).** `SYNC_PUSH` entries
  gain the subject's `lastCommit` id (and, where available, the signed envelope for
  ops past it). The importer can then either (a) verify and record provenance, or
  (b) for the same-agent-replica case, at minimum refuse entries whose claimed
  provenance doesn't check out. Interim, cheaper step: on reconnect, **block VV push
  for subjects with a pending outbox entry** — the drain is the only writer for dirty
  subjects; VV sync covers only subjects the outbox doesn't know about. That closes
  the unsigned-write race without a wire change.

## Trust and authority

See also [`atomic-lib-runtime.md` § Authorization](./atomic-lib-runtime.md#authorization)
and [`sync.md` § Deletes over bulk sync](./sync.md#deletes-over-bulk-sync).

### Default (canvas v1): hub + signed commits

For **phone + tablet + web** on the **same agent**, the configured server is the source
of truth. Clients are offline-first **replicas**:

- **Trust:** commits applied on the hub (rights-checked) and pushed to subscribers.
- **Do not trust:** Iroh `NodeID` alone, QR scan alone, bulk `SYNC_DIFF` as a second
  authority over deletes, or **any drive/class value carried inside incoming CRDT
  payloads** (F2).

### Two sync layers (do not conflate)

```text
Layer 1 — Commit log (authoritative)
  mutate → dirty bit → outbox drain → sign ONE commit/subject → COMMIT → hub apply + rights
  → other clients: UPDATE / DESTROY

Layer 2 — Bulk reconcile (same-agent catch-up / offline gap)
  SYNC → SYNC_DIFF { pull, push, remove, pullFrom } → SYNC_PUSH
  Loro VV diff + local tombstones — target: provenance-carrying (F1)
```

| Layer | Proves identity | Proves rights | Deletes |
| --- | --- | --- | --- |
| **1 — Live / COMMIT** | WS `AUTH` or HTTP auth | Hub `apply_commit` + hierarchy | Signed destroy commit → `DESTROY` |
| **2 — Bulk** | `AUTH` on stream before `SYNC` (enforced on Iroh accept 2026-09-01; WS gates writes + identity-bearing subs, anonymous reads stay `check_read`-gated) | `check_read` on push; `check_write` + admission on import | `remove[]` plus `removeCommits` when the sender still holds the destroy envelope (applied as a peer `COMMIT`); unsigned entries stay admission-gated |

**Policy:** authoritative delete = Layer 1 on the hub. Layer 2 `remove` only prevents
resurrection between honest replicas of the same agent.

## Unified API sketch

Align with [`atomic-lib-runtime.md`](./atomic-lib-runtime.md) (`SyncService`,
`NodeEvent`, `AtomicTransport`):

```rust
pub enum Subscription {
    Drive(Subject),
    Query { property: String, value: String, drive: Subject },
    Resource(Subject),
}

pub enum NodeEvent {
    ResourceChanged { subject: Subject, source: ChangeSource, .. },
    ResourceDestroyed { subject: Subject, source: ChangeSource },
    QueryChanged { filter: QueryFilter, added: Vec<Subject>, removed: Vec<Subject> },
    SyncStateChanged { drive: Subject, state: SyncState },
}

impl AtomicNode {
    pub fn subscribe(&self, sub: Subscription) -> NodeEventStream;
    /// Drains the dirty-subject outbox over the given transport
    /// (pipelined COMMIT frames — see Outbox modernization).
    pub async fn drain_outbox(&self, transport: &mut impl AtomicTransport) -> ..;
    pub async fn run_sync_session(&self, transport: impl AtomicTransport, drive: Subject) -> ..;
}
```

The outbox inside `AtomicNode` is the ported `LocalOutbox` (dirty bit + genesis
envelope + `baseVersion` + backoff/blocked), not a signed-commit queue.

**WS adapter:** `atomic_lib::client::ws::WsClient`. **Iroh adapter:** existing
`peer.rs` live stream — should emit the same `NodeEvent`s after import.
**Flutter bridge (FRB):** `subscribe_events`, `open_sync_session(server_url)`,
`close_sync_session` — not `peer_sync` / `watch_children`.

## Related plans

| Doc | Relationship |
| --- | --- |
| [`atomic-lib-runtime.md`](./atomic-lib-runtime.md) | Owns `AtomicNode`, `NodeEvent`, `AtomicTransport`. |
| [`sign-at-drain.md`](./sign-at-drain.md) | Outbox dirty-bit model (shipped); protocol cleanups this doc schedules. |
| [`commit-retention-and-state-certificates.md`](./commit-retention-and-state-certificates.md) | Commit-as-state-certificate; idempotent replay that makes re-drain safe. |
| [`sync.md`](./sync.md) | WS `COMMIT` / echo suppression — done; test coverage gaps. |
| [`unified-data-layer.md`](./unified-data-layer.md) | Browser cache on top of node API. |
| [`virtual-drive.md`](./virtual-drive.md) | VFS subscribes to the same watched-queries cache. |
| [`serverless-p2p.md`](./serverless-p2p.md) | **Option B execution plan** — same-agent device sync without a hub; owns F9-proper, OQ4/OQ6 resolutions, pairing, and the Iroh `SyncSession` transport. |
| [`completed/unified-sync-audit-2026-07.md`](./completed/unified-sync-audit-2026-07.md) | As-built record: the 2026-07 audit findings F1–F12, the inventories, and the closed phase checklists. |

## Open questions

Findings referenced by number (F1–F12) are written up in
[`completed/unified-sync-audit-2026-07.md`](./completed/unified-sync-audit-2026-07.md).

1. **Embedded server on mobile** — every install its own server, or shared hosted
   instance? (Affects `serverUrl` default.)
2. **Iroh default** — ✅ **Decided 2026-07-02: Option B** (serverless P2P is a
   product requirement; plan in [`serverless-p2p.md`](./serverless-p2p.md)).
   Unblocks F9-proper; resolves OQ4 below (signed destroy commits) and OQ6
   (same-agent AUTH proof *is* the pairing).
3. **Layer 2 provenance depth** — is `lastCommit`-id-only enough for same-agent
   replicas, or must `SYNC_PUSH` carry verifiable signed envelopes end-to-end
   (overlaps the high-audit profile in [`sign-at-drain.md`](./sign-at-drain.md))?
4. **P2P `remove` policy** — ✅ **Resolved 2026-07-02 with OQ2**: destroys
   become signed commits on the wire (see
   [`serverless-p2p.md`](./serverless-p2p.md) § Destroys). Decision closed;
   the implementation item there is still unchecked — today the live
   `DESTROY` frame and `remove[]` are accepted but gated by the drive-level
   write verdict (`lib/src/sync/peer.rs`). Original question: accept peer
   tombstones for same-agent reconcile, or only hub-signed destroys?
5. **Bootstrap admission (F2)** — ✅ **Closed 2026-09-05** via
   `admit_unknown_drive`: `Public` never creates a drive; Owner is
   reject-until-known (signer is the node owner, then enrolled);
   `OpenPolicy` still admits an authenticated first-sync (localhost
   create-account / same-agent first-sync); `AllowlistPolicy` grace is
   unchanged for managed nodes. F2's existing-resource spoof was already
   closed (`989a8751`); the remaining missing-drive `Err(_) => true` ACL
   skip in `admitted_for_drive` is gone.
6. **What makes a peer "known"? (F9)** — ✅ **Resolved**: first with OQ2
   (2026-07-02, "same-agent AUTH *is* the pairing"), then reframed 2026-07-17
   (`683a25d4a`) — AUTH admits any agent, rights decide what crosses, and
   `KnownPeer` is persisted based on who dialed
   ([`device-pairing.md`](./device-pairing.md),
   [`sync-onboarding-ux.md`](./sync-onboarding-ux.md)). Original text, kept
   for context: today: any inbound connection. The fix says
   "pairing or explicit user action," but the pairing primitive itself is undefined
   (QR scan is one-directional trust; see [`sync.md`](./sync.md)'s handshake notes and
   the constrained append-only inbox in
   [`authorization-sync.md`](./authorization-sync.md)). Decide what ceremony grants
   known-peer status before rebuilding the accept path around it.
