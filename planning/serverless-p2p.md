# Serverless P2P — same-agent device sync without a hub

> **Status:** Planned (2026-07-02). This doc records the **Option B decision**
> from [`unified-sync.md`](./unified-sync.md) Open Question 2: serverless P2P
> (e.g. Android ↔ Android) is a product requirement, so the Iroh path gets
> hardened and unified rather than deleted. Supersedes the "A for canvas v1"
> default recommendation.
>
> Prereqs and open findings referenced here (F1, F9-proper, OQ4–OQ6, the
> consolidation inventory) live in [`unified-sync.md`](./unified-sync.md).
>
> **Current (2026-07-17).** The same-agent admission rule this document was
> written around was removed in `683a25d4a` ("authorize relayed sync by owned
> drive, not peer identity"): `is_same_agent_as_ours` no longer exists, peer
> `AUTH` proves *an* agent, and what crosses the link is decided per subject by
> `check_read` and per drive by `may_accept_drive_write`
> (`lib/src/sync/engine.rs`); `KnownPeer` persistence is gated on who dialed
> ([`device-pairing.md`](./device-pairing.md)). Every "same-agent only" /
> "same agent ⇒ trust" line below is superseded wording — the newest statement
> of the model is [`sync-onboarding-ux.md`](./sync-onboarding-ux.md) (2026-07-17).
> Same-agent pairing is still the *first* product use, which is why the
> remaining text reads as it does; it is no longer the gate.

## Goal

Two Android devices (later: any two nodes) holding the **same agent** sync a
drive directly over Iroh — pairing, initial reconcile, live updates, offline
edits draining on reconnect — with **no server anywhere**, and with the same
trust guarantees the hub path gives today.

Cross-agent P2P *sharing* is explicitly out of scope here (separate product;
primitives in [`authorization-sync.md`](./authorization-sync.md)). Same-agent
comes first because its trust model is radically simpler — see Principle 1.

## Design principles

Everything in this plan follows from five rules. When a design question comes
up, answer it from these, in order:

1. **The agent key is the only trust root.** NodeIDs route, QR codes
   bootstrap discovery — neither authorizes anything. Two devices trust each
   other iff each proves possession of an acceptable agent key over `AUTH`.
   For same-agent sync this collapses beautifully: *proving you hold the same
   agent key IS the pairing*. No consent ceremony needed beyond the key
   itself.
2. **Every peer is a hub.** There is no "server code" vs "peer code": the
   same `engine::handle_frame` validates every inbound frame on every node,
   with the same signature checks, rights checks, and admission gates. A
   serverless peer receiving a `COMMIT` applies it exactly like
   atomic-server does. This is what makes serverless *possible* without a
   second trust model — and it's why the consolidation work (engine owns all
   tags) is a prerequisite, not a nice-to-have.
3. **Signed commits are the unit of authority on every transport.** The
   outbox drains `COMMIT` frames to whichever replica is reachable — hub or
   peer. Destroys travel as signed destroy commits, never as naked `DESTROY`
   frames (this answers OQ4: tombstone authority = a destroy commit whose
   signature and rights verify locally). Raw CRDT state transfer
   (`SYNC_PUSH`) is an *optimization* permitted only between
   mutually-authenticated same-agent replicas.
4. **Pairing is an explicit, persisted capability grant.** A `KnownPeer`
   record means "this NodeID may be auto-dialed for these drives as this
   agent" — written only by explicit user action (QR scan + same-agent AUTH
   proof), never by an inbound connection (F9-minimal, already shipped).
5. **Fail closed on identity.** No `SYNC`, `SYNC_PUSH`, or live frames
   processed before `AUTH`; pre-auth frame budgets stay tight; an
   unauthenticated peer gets `ERROR` and a closed stream, not `Public`
   semantics.

## Why same-agent-first makes this tractable

The scary parts of P2P (consent ceremonies, grant chains, adversarial
tombstones, relay trust) all come from *cross-agent* scenarios. Same-agent
multi-device has none of them:

- **Identity:** both devices sign with the same key. Mutual `AUTH` proves it.
  An attacker without the key can pair with nobody, read nothing, write
  nothing — regardless of NodeID knowledge.
- **Rights:** trivially symmetric. Everything one device may read/write, the
  other may too. `check_read`/`check_write` still run (Principle 2), they
  just never disagree.
- **Deletes:** a signed destroy commit from your own agent is
  self-evidently authorized.
- **Conflict:** Loro CRDT merge, same as today.

So the plan hardens the general machinery (because Principle 2 demands it and
cross-agent will come later) while shipping only the same-agent product.

## Architecture target

```text
Android A                          Android B
┌───────────────────────┐          ┌───────────────────────┐
│ UI (CanvasStore, …)   │          │ UI                    │
│   ↕ NodeEvent stream  │          │   ↕ NodeEvent stream  │
│ AtomicNode            │          │ AtomicNode            │
│  · Db (redb)          │          │  · Db (redb)          │
│  · Outbox (ported)    │          │  · Outbox (ported)    │
│  · engine::handle_-   │◄──Iroh──►│  · engine::handle_-   │
│    frame (ALL tags)   │  QUIC    │    frame (ALL tags)   │
└───────────────────────┘          └───────────────────────┘
        ▲                                   ▲
        └──── same frames, same engine ─────┘
     (a hub, when configured, is just another peer
      that happens to be always-on)
```

`SyncSession { transport: IrohTransport | WsTransport }` owns the lifecycle:
connect → mutual AUTH → VV reconcile → live mode → outbox drain on dirty.
One state machine replaces today's handshake/live duality in `peer.rs`.

## Account state: the agent resource syncs too

**Shipped (2026-07-10).** Same-agent sync must carry more than drives. The
agent resource itself — `did:ad:agent:<pubkey>`, holding the account `name`,
its `drives` list, `publicKey` — is owned by itself and sits **outside every
drive's subtree**. Drive sync walks the `parent` index down from a drive root
(`collect_drive_subjects`), so it structurally never reaches the agent. The
symptom: a device signed in from a secret gets only what `Agent::from_secret`
→ `to_resource` builds — `publicKey` and a `drives` list seeded from the
secret's `initial_drive`, but **no name**. Create a new drive on that device
and the switcher (which reads `agent.drives`) can no longer show the drive you
paired in, because a pairing-pull sets `active_drive` without appending to
`agent.drives`. Two symptoms, one cause: the agent resource never crossed.

The fix follows directly from the principles. Both devices are mutually
authenticated as the **same agent** (Principle 1), and an agent may always
write its own resource (`hierarchy::check_write`: "Agents can always edit
themselves"). So on connect each side hands the other its agent resource as an
ordinary `UPDATE` (Principle 3's same-agent raw-state exception — no new frame,
no signature ceremony), and Loro merges the two independent docs: `name` is a
last-writer-wins register, `drives` is a CRDT list that **unions**, so every
drive any device knows becomes visible on all of them.

Guarded and echo-safe:
- Pushed only when the peer is same-agent (`is_same_agent_as_ours`) — the agent
  resource is your identity root; it must never be sent to, or accepted from, a
  stranger. A peer may only reconcile *its own authenticated* agent subject
  (`is_our_agent_subject`), never an arbitrary one.
- Applied under the importing flag so the live push loop doesn't re-broadcast
  it (two sides pushing identical snapshots would otherwise ping-pong). The WS
  announcer ignores that flag, so the on-device browser still repaints with the
  merged name / drives.

Implementation lives in `peer.rs` (`own_agent_update_frame`,
`is_our_agent_subject`, the `register_live_peer` push, the read-loop
suppression); e2e test `same_agent_peers_reconcile_the_agent_resource`.
This is a targeted fix on today's `peer.rs`; it folds into `SyncSession`'s
post-AUTH reconcile when P2 lands (the agent subject is just another entry in
the VV set, alongside the drive roots).

## Phases

### P0 — Trust prerequisites (harden what exists)

The F9-proper cluster, previously gated on this very decision — now
unblocked:

- [x] **Initiator-side `check_read`** on `SYNC_DIFF.pull` serving (2026-07-07)
  — was raw `Tree::LoroSnapshots` reads. New `collect_pull_snapshots`
  (peer.rs) gates every pulled subject on `check_read` for the identity the
  peer proved via auth-back, mirroring the acceptor's `handle_sync_vv`; fails
  closed (a subject that doesn't materialize isn't served). Covers both the
  no-SYNC_PUSH and the post-SYNC_PUSH pushback sites.
- [x] **Replace the initiator's `ForAgent::Sudo` import** with the auth-back
  agent (2026-07-07). `sync_drive_with_peer_using_outcome`'s `import_sync_push`
  call now passes `remote_agent` (the identity proven by the peer's auth-back
  AUTH, which the accept side writes right after `AUTH_OK`, before any SYNC_*
  frame, on the ordered QUIC stream) instead of `Sudo`. `import_sync_push`'s
  existing drive-level `check_write` + admission gate now actually bite;
  same-agent replicas still import (auth-back proves the shared key → write
  rights hold). Initiator's `SYNC_DIFF.remove[]` apply is gated the same way
  via `apply_peer_remove` (admission + ACL, like a live `DESTROY`) — closes
  the F10 known-subject residual too. Four regression tests
  (`sync::peer::initiator_trust_tests`), each proven against a reverted build
  (3 fail vulnerable, owner-still-works stays green); full 64-test sync suite
  incl. real two-endpoint Iroh e2e green.
- [x] **Require `AUTH` before `SYNC`/`SYNC_PUSH`/live frames** on accept
  paths; reject instead of defaulting to `Public`. (2026-09-01: Iroh
  `handle_stream` and the accept-side live loop answer `ERROR AUTH_REQUIRED`
  and close; WS gates writes and identity-bearing subscriptions, anonymous
  reads stay `check_read`-gated. `sync::peer::accept_gate_tests`.)
- [x] **Bind `AUTH.requestedSubject` to the session's drive** so a proof for
  one drive can't be replayed against another. (2026-09-01, Iroh accept
  path; the browser signs the server origin so WS has nothing to bind.)
- [x] **Destroys become signed commits on the live link** (Principle 3,
  2026-09-03): the Iroh push loop forwards the signed destroy `COMMIT`
  (carried on `DbEvent::Destroyed::commit_json`) and the live read loop
  ignores a naked `DESTROY` from any peer, owner included; the engine's
  COMMIT arm validates signature and rights. Tests:
  `sync::peer::accept_gate_tests::{naked_destroy_on_the_live_link_is_ignored,
  signed_destroy_commit_on_the_live_link_is_applied,
  signed_destroy_from_stranger_on_the_live_link_is_refused}`.
- [x] **Bulk `remove[]` carries a signed destroy when the sender still holds
  it** (2026-09-05): the tombstone value is the commit JSON-AD (or a
  one-byte unsigned marker). `SYNC_DIFF.removeCommits` attaches those
  envelopes; the receiver applies them as a peer `COMMIT` and does not
  fall back to the unsigned path on a bad signature. Unsigned entries
  stay admission-gated for senders that never stored the envelope.
  Requiring an envelope on every `remove[]` still waits on
  `Tree::Envelopes` (commit-retention floor).
- [x] Pre-auth frame budget in the live read loop (the `matches!(agent,
  Public)` gate exists in `handle_stream`; mirror it in
  `register_live_peer`). (2026-09-01: the live loop now refuses every
  non-AUTH frame from a still-`Public` peer we did not dial, which
  subsumes the budget.)
- [x] (2026-09-05) **OQ5:** a drive this node has never stored is admitted
  only through `admit_unknown_drive`. `Public` never creates one. Owner
  enrolls only the owner. Open still admits an authenticated first-sync
  (same-agent devices on `OpenPolicy` keep working). Pairing-as-explicit
  enrollment of specific drives (`KnownPeer` capability records) remains P3.

### P1 — Consolidation (the "cleanly" part; build on one engine, not two)

From the [consolidation inventory](./unified-sync.md#consolidation-inventory-2026-07-02-third-pass),
now load-bearing rather than hygiene:

- [~] **Engine owns ALL tags** — *AUTH + GET + COMMIT-apply done (2026-07-07);
  server COMMIT converged same day:* AUTH and GET now delegate to
  `engine::handle_frame` (the engine resolves `internal:/` against its own base
  domain — no hook needed — closing the drift bug). The engine also gained a
  `COMMIT` arm (`apply_peer_commit`): a peer routing a `COMMIT` through the
  engine applies it with full signature + rights validation, which is the
  "every peer is a hub" write path serverless P2P needs (P4). **Server COMMIT
  now delegates too:** `engine::ingest_commit_json(store, commit_json,
  &CommitIngestOpts)` is the single implementation; the server's
  `apply_commit_json` and the engine's `apply_peer_commit` are both thin
  wrappers. The "fan-out/source_id hook" this item used to call out turned out
  not to need a `handle_frame` signature change — `source_id` is just a field
  on `CommitIngestOpts`, and the hub's per-source echo-suppression /
  domain-ownership / Loro-causality gates are opts booleans the peer path
  leaves off. **`SUB`/`UNSUB` parse + `check_read` live in
  `handle_frame_full` (2026-09-05);** the WS handler still `do_send`s to the
  commit monitor because the engine has no actor mailbox.   Folding
  `LoroSyncBroadcaster` into `CommitMonitor` landed 2026-09-05. AUTH+GET
  were the pure request→response pair that had actually drifted; COMMIT-apply
  was the additive capability peers needed, and is now one implementation
  instead of two.
- [ ] **`trusted_hub` / `untrusted_peer` module split** in `ws_apply.rs` so
  the unconditional apply paths can't be reached from accept code.
- [ ] Collapse the remaining four `sync_drive_with_peer*` variants (two of
  the six were dead or single-use indirections, removed 2026-09-04) into one
  `SyncSession::run(transport, drive, opts)`.
- [x] (2026-09-04) Key `LIVE_CONNECTIONS` by peer + prune with `remove_live_peer` (leak).
- [ ] Delete the remaining dead client surface (`WsMessage::Resource`/
  `Commit` variants + parser arms, unused `WsClient` methods) so the
  transport trait starts from a minimal honest API.

### P2 — Port the outbox + unified session API to Rust

- [~] **`AtomicTransport` trait + `SyncSession::serve`** (2026-09-05):
  `lib/src/sync/transport.rs` (`AtomicTransport`, in-process
  `ChannelTransport`) and `lib/src/sync/session.rs` (responder loop over
  `handle_frame_full`). `IrohTransport` / `WsTransport` wrappers are not
  wired; `handle_stream` / `register_live_peer` still own the Iroh
  lifecycle.
- [ ] **Port `LocalOutbox` semantics into `atomic_lib`** (`AtomicNode`
  outbox): dirty bit, genesis envelope, `baseVersion`, backoff, blocked
  states, structured-error classification. Android needs durable offline
  queuing exactly like the browser; Flutter's `try_push_commit` is not it.
- [ ] **`SyncSession` state machine** beyond the responder loop: connect →
  mutual AUTH (fail closed) → VV reconcile → live → drain-on-dirty;
  reconnect with backoff; emits `NodeEvent`s. Replaces `handle_stream` +
  `register_live_peer` + the auto-connect loop's inline logic.
- [ ] **FRB surface**: `subscribe_events`, `open_sync_session(target)`,
  `close_sync_session`, where `target` is a server URL *or* a paired
  NodeID. `pollDbEvent`, `peer_sync`, `watch_children` are deleted.

### P3 — Pairing (the only new UX)

Same-agent pairing needs no consent dialog — the key is the consent
(Principle 1):

- [ ] **QR contains routing only**: NodeID (+ relay hint). Scanning it dials
  the peer; both sides then mutual-`AUTH`.
- [x] ~~**Auto-accept iff same agent**~~ — superseded 2026-07-17 (see the
  *Current* note at the top): AUTH admits any agent; the acceptor persists
  `KnownPeer` based on who dialed, and rights decide what each side may read
  or write. Cross-agent pairing therefore needs no separate admission path,
  only the knock/inbox primitive in
  [`authorization-sync.md`](./authorization-sync.md) for *granting* rights.
- [ ] **`KnownPeer` becomes a capability record**: `{node_id, agent,
  drives[], name, paired_at}` — not just an address. Auto-connect dials only
  peers with a record, only for the drives in it.
- [ ] Both sides show "Paired with <device name>" (HELLO name, display-only,
  as today).

### P4 — Ship same-agent Android ↔ Android

- [~] Outbox drains `COMMIT` frames over the Iroh session when it's the
  reachable transport (Principle 3 — the peer applies with full validation
  via the engine's COMMIT arm from P1). **The receiving half is done
  (2026-07-07):** `engine::handle_frame` now has a `COMMIT` arm
  (`apply_peer_commit`) that validates signature + schema + the signer's
  rights and answers `COMMIT_OK`/`ERROR`, so any peer transport routing
  through the engine (the Iroh live loop already falls through to it) applies
  commits exactly like the server's path — "every peer is a hub" for writes.
  Gated by the commit's own signature, not the connection's AUTH (a relayed
  valid commit grants only what its signer could already do); causality +
  previous-commit checks off for concurrent peer writes, but timestamps ARE
  validated (replay bounding). Tests:
  `engine_commit_from_authorized_signer_is_applied` /
  `..._unauthorized_signer_is_rejected` (rights gate revert-proven). **Still
  to do:** the *sending* half — the outbox actually draining `COMMIT` frames
  over an Iroh `SyncSession` (needs P2's outbox port + session).
- [ ] `SYNC_PUSH` fast-path kept for initial reconcile between the two
  same-agent devices (permitted by Principle 3's exception; both sides have
  proven the same key).
- [ ] **Android lifecycle**: sync on foreground/resume; optional foreground
  service for "sync while charging on LAN"; Iroh endpoint teardown on
  background (WS-suspension notes in
  [`unified-sync.md`](./unified-sync.md#mobile-specific-notes) apply
  doubly).
- [ ] Adversarial e2e tests alongside the happy path: unauthenticated peer
  gets zero frames past AUTH; wrong-agent peer rejected at pairing; naked
  DESTROY ignored; replayed AUTH for another drive rejected.
- [ ] Manual test matrix: two Android devices, airplane-mode Wi-Fi Direct /
  LAN, kill-and-resume, clock skew.

### P5 — Later (explicitly not now)

- Cross-agent sharing over P2P (knock/inbox ceremony, grant chains) —
  [`authorization-sync.md`](./authorization-sync.md).
- Provenance-carrying `SYNC_PUSH` (per-entry `lastCommit`/envelopes) — the
  F1 full fix; becomes *required* the day relaying or cross-agent P2P
  exists, because then state transfer crosses trust boundaries.
- Multi-peer topologies (>2 devices, mesh gossip), Reticulum/LoRa transport
  ([`reticulum-sync.md`](./reticulum-sync.md)), NAT-hostile relay policy.
- High-audit per-change signatures
  ([`sign-at-drain.md`](./sign-at-drain.md) § profiles).

## What gets deleted (yes, deleted — B is not "keep everything")

Choosing B does not mean keeping today's P2P code. The `SyncSession` +
one-engine architecture replaces, not wraps:

| Today | Fate |
| --- | --- |
| `handle_stream` / `register_live_peer` handshake-vs-live duality | Replaced by `SyncSession` state machine |
| Auto-connect loop's inline retry/dial logic | Replaced by session reconnect policy over `KnownPeer` records |
| Six `sync_drive_with_peer*` entry points | One `SyncSession::run` |
| Naked `DESTROY` acceptance + peer `remove[]` authority | Signed destroy commits (OQ4 closed) |
| `poll_sync_events` / `wait_for_*` FRB trio | `NodeEvent` stream |
| Server's hand-rolled AUTH/GET/COMMIT/SUB arms | Engine-owned (P1) |
| Flutter `try_push_commit` partial outbox | Ported `AtomicNode` outbox |

## Sequencing note

P0 and P1 interleave with the already-planned unified-sync Phase 0b/2 work
and are useful even if this plan stalls. P2 is the biggest lift (outbox port
+ session state machine) but is *also* what unified-sync Phase 1 ("WS session
on mobile") wants — one investment serves both transports. P3+P4 are the
genuinely new work, and they're small once P0–P2 exist. That's the "cleanly"
claim in concrete terms: the serverless feature itself is thin; almost all
the work is hardening and consolidation the codebase needs anyway.

## Open questions

1. **Relay dependency** — Iroh's `discovery_n0()` uses public relays for
   NAT traversal. Is "serverless" allowed to depend on a relay for
   *routing* (never trust — Principle 1 — but availability)? LAN-only mode
   (mDNS discovery) as a fallback?
2. **Battery budget** — foreground-only sync vs a persistent service; what
   does "live" mean when both apps are backgrounded?
3. **Key transport** — same-agent pairing assumes the agent secret already
   exists on both devices (today: paste/QR the secret). Does secret
   provisioning ride the same QR flow as NodeID exchange, and if so, how is
   it protected in transit? **Resolved in
   [`device-pairing.md`](./device-pairing.md):** no. The QR is routing only,
   and a code carrying a secret is refused — any app or web page can fire an
   `atomic://` link, so a link must never sign a device in. A new device
   signs in by entering its secret; channel-provisioning behind an on-screen
   confirm is P3.
4. **Drive enrollment on pairing** — pair grants which drives? All of the
   agent's, or picked at pair time (`KnownPeer.drives`)?
