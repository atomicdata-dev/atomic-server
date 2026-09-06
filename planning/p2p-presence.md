# P2P presence — ephemeral awareness over the Iroh live channel

> **Status:** Mostly built (2026-09-03). The `EPHEMERAL (0x40)` codec
> (`lib/src/sync/protocol.rs`, `ephemeral_frame_tests`), the peer send/receive
> path (`broadcast_ephemeral` + the `0x40` arm in `register_live_peer`) and the
> server bridge (`CommitMonitor` presence maps; was `LoroSyncBroadcaster`) are in, with an Iroh e2e
> (`e2e_presence_crosses_the_link_without_being_stored`) proving presence crosses
> the link and reaches no store. Open: the two-device verification below (M12 in
> [`pairing-ux-field-test.md`](./completed/pairing-ux-field-test.md)) and OQ1 bandwidth.
> Originally written 2026-07-10 as a proposal; the rest of this doc is that
> design. Extends the shipped browser presence
> model ([`presence-views.md`](./presence-views.md)) to travel device-to-device
> over the serverless Iroh transport ([`serverless-p2p.md`](./serverless-p2p.md)),
> so a user's own devices show each other's cursors and "viewing / following /
> typing" state with no hub in the path.
>
> Depends on the same-agent peer link being live (shipped: pairing, reconnect,
> live `UPDATE` fan-out). Cross-agent multi-user presence over P2P is **out of
> scope** — see [Scope](#scope-my-devices-not-collaborators).
>
> **Current (2026-07-17).** Peer sync is no longer same-agent only:
> `is_same_agent_as_ours` was removed in `683a25d4a` and admission is
> rights-based (`check_read` per subject; see
> [`sync-onboarding-ux.md`](./sync-onboarding-ux.md)). The *scope choice* here
> (presence only between your own devices) still holds as a product decision,
> but Decision 8 ("same-agent is the whole ACL") can no longer lean on the
> transport — a cross-agent peer can be connected, so the outbound filter in
> OQ3 (`PresenceEntry.agent == our agent`) becomes the actual gate, not a
> belt-and-braces one. Wording below that assumes the old rule is superseded.

## Goal

An edit already propagates between two paired devices' open documents with no
button press (live `UPDATE` frames over Iroh). Presence should ride the same
link: move your cursor on the tablet, and the phone's open document shows it;
open a resource on one device, and your other devices show you there. All of it
**ephemeral** — never signed, never stored, never a commit.

## Scope: my devices, not collaborators

Peer sync is **same-agent only** (serverless-p2p Principle 1: two devices trust
each other iff each proves the same agent key). So P2P presence here means
*your own devices seeing each other* — cross-device continuity ("editing on
your phone", follow-me across devices), not collaborators in a shared drive.

Multi-user presence already works **over the hub** (the WS
`CommitMonitor` relays between different agents' sessions, gated on drive
`check_read`). Multi-user presence *over P2P* needs the cross-agent grant model
that doesn't exist yet ([`authorization-sync.md`](./authorization-sync.md)) and
is explicitly not part of this plan. The frame designed below is agnostic to
that, so nothing here blocks it later.

## Where presence lives today

Two ephemeral channels, both browser-only, both terminating at the WS server.
Neither has any path to Iroh.

1. **Drive presence** — `browser/lib/src/presence.ts`. One
   `DrivePresenceManager` per drive wraps a Loro `EphemeralStore`; each session
   writes one key (`sessionId`) holding a `PresenceEntry` (`agent`, `resource`
   viewed, `following`, `session`, `typing`, view `data`). 30 s TTL, 10 s
   heartbeat (`PRESENCE_TTL_MS` / `HEARTBEAT_MS`, `presence.ts:40-43`).
   Transported as opaque bytes: a `PRESENCE_SUBSCRIBE` text frame to
   register, then binary `EPHEMERAL (0x40)` frames of kind `PRESENCE` both
   ways (text `PRESENCE_UPDATE` until 2026-09-04).
2. **Document cursors** — `browser/data-browser/src/chunks/RTE/useLoroSync.ts`.
   A *separate* per-document `CursorEphemeralStore` (loro-prosemirror), synced
   over `EPHEMERAL` frames of kind `LORO` (text `LORO_EPHEMERAL_UPDATE`
   until 2026-09-04). Deliberately not on the drive
   channel: cursor anchors are Loro `Cursor` objects tied to the document oplog
   and move per keystroke.

Server relay: `server/src/commit_monitor.rs` — the same actor that fans
commits also holds the Loro-ephemera and drive-presence maps. It relays both
channels opaquely, gates drive presence on `check_read` at subscribe,
caches each connection's latest `encodeAll()` payload and
replays it to late joiners. It is constructed with a `Db` and
**has no reference to Iroh**; `serve.rs` is the bridge.

## Why it doesn't cross to peers today

The P2P live channel (`lib/src/sync/peer.rs`) is the mirror image of the
presence channel:

- Its **source** is exclusively `store.subscribe_events()` — persisted commits
  (`peer.rs:445,463-467`). Presence is never a commit, so the push loop never
  sees it. The one "push arbitrary bytes" entry point, `broadcast_live_update`
  (`:419`), has a single caller that feeds it persisted commit deltas
  (`flutter/rust/src/api/simple.rs:23`).
- Its **sink** always persists: an inbound `UPDATE` runs `admitted_for_drive`
  (ACL `check_write`) then `ws_apply::persist_update` — written to disk as CRDT
  state (`peer.rs:834-875`).

So the two live worlds never touch, and an ephemeral payload sent as `UPDATE`
would be *wrongly written to disk*.

There is already a reserved wire tag — `EPHEMERAL = 0x40`
(`lib/src/sync/protocol.rs:45`) — with **no** encoder, decoder, or handler
anywhere. That reservation is the intended home for this work.

## Design decisions

Grounded in the serverless-p2p principles; answer new questions from these.

1. **A distinct `EPHEMERAL 0x40` frame, never an overloaded `UPDATE`.**
   `UPDATE`'s receive path always persists and runs `check_write`. Presence
   must do neither. Keeping them separate structurally guarantees cursor spam
   can never land on disk — the property we want is enforced by the frame type,
   not by a flag someone can forget. (Rejected: an `UPDATE` "don't-persist"
   flag — one wrong branch and presence is durable.)

2. **The frame is transport-mechanical; `lib` never interprets the payload.**
   `0x40` carries: a small **channel discriminator** (drive-presence vs
   document-cursor), the **scope** it belongs to (drive subject, or resource
   subject for cursors), and an **opaque byte blob** (the Loro `EphemeralStore`
   / `CursorEphemeralStore` `encodeAll()` output). `peer.rs` moves bytes; only
   the browser encodes/decodes them. This mirrors how the WS broadcaster treats
   presence as opaque.

3. **The bridge lives in the server, not in `lib`.** Only the server process
   can see both `LoroSyncBroadcaster` (WS presence) and `peer.rs`'s
   `LIVE_PEERS` (Iroh fan-out). `lib` stays a pure transport with no knowledge
   of the WS actor. On a Tauri/Android device the embedded server is exactly
   this bridge; on the hub it is the same code, unused unless a peer link
   exists.

4. **Relay, never persist, never emit a `DbEvent`.** The `peer.rs` read loop
   special-cases `0x40`: hand the payload to the local bridge, which (a) injects
   it into the local `LoroSyncBroadcaster` so this device's own browser tab sees
   it, and (b) does *not* call `persist_update`, `apply_commit`, or
   `db_events.send`. Presence leaves no trace once the session ends.

5. **TTL is end-to-end; the transport is dumb.** The browser `EphemeralStore`
   already owns expiry (30 s TTL, 10 s heartbeat, LWW by timestamp). The peer
   relay just moves the latest `encodeAll()` blob. A peer that drops off the
   mesh stops heartbeating; its entries expire on every device naturally. No
   liveness logic in Rust.

6. **One-hop relay, no store-and-forward.** Your devices form a near-full mesh
   (each auto-connects to each known peer — `peer.rs:164-235`), and the count
   is small. A `0x40` frame goes to every *directly connected* live peer plus
   the local WS, and is **not** re-forwarded. This avoids gossip loops without
   dedup bookkeeping. (Revisit only if a real topology appears where two of a
   user's devices can reach each other only via a third.)

7. **Echo suppression by source.** A frame that arrived from peer X must not be
   sent back to X, and a frame injected into the local WS from a peer must not
   be re-emitted back onto Iroh. Reuse the `source_id` discipline the commit
   fan-out already uses (`skip_same_source`).

8. **Same-agent is the whole ACL.** Between your own devices the peer already
   proved it holds your agent key (`is_same_agent_as_ours`, enforced on both
   sides). There is no per-drive `check_read` to run on the peer side — it's all
   you. (The hub keeps its `check_read` gate for the multi-user case; that path
   is unchanged.)

## Work breakdown

Additive; nothing here changes the persistent `UPDATE`/`COMMIT` paths.

1. **Wire the `0x40` frame** — `encode_ephemeral` / `decode_ephemeral` in
   `lib/src/sync/protocol.rs` (channel discriminator + scope subject + opaque
   blob), plus the JS mirror in `browser/lib/src/ws-v2.ts` (currently only lists
   `0x40` in the tag→name map, no codec).

2. **Peer receive handler** — in `register_live_peer`'s read loop
   (`peer.rs:~834`), special-case `0x40` alongside `UPDATE`/`DESTROY`: decode,
   hand to the bridge callback, **continue** (never fall through to persist).

3. **Peer send path** — a `broadcast_ephemeral(scope, channel, blob)` beside
   `broadcast_live_update`, fanning to `LIVE_PEERS` via the existing
   `send_live_update_wire_msg`, with source-tag echo suppression.

4. **The server bridge** — connect `LoroSyncBroadcaster` ⇄ peer channel:
   - Outbound: when the broadcaster relays a presence or cursor update,
     also call `broadcast_ephemeral` for the peers syncing that drive.
   - Inbound: the peer read handler's bridge callback injects the blob into the
     broadcaster as if a local WS client had sent it, so the on-device browser
     renders it.
   - Scope the bridge to the drives this node actually syncs (the same
     `active_drive` / known-peer set the reconnect loop uses).

5. **Frontend** — nothing structural. Presence already flows over WS to the
   embedded server; the bridge makes it cross to peers transparently. Confirm
   `PresenceEntry.agent` colouring and `sessionId` uniqueness hold when the same
   agent appears from two devices (expected: two sessions, two dots — the
   `sessionId` already distinguishes them, `presence.ts`).

## Verification

Two paired devices, same agent, both on the same open document:

- Move the cursor / select a table cell / pan a canvas on device A → device B
  shows it within a frame or two, no reload, no "Sync now".
- Open resource X on A → A appears in B's facepile / sidebar dots as viewing X.
- Kill A (or drop its link) → A's presence disappears from B within the 30 s
  TTL, with no explicit "left" signal.
- Confirm **nothing** is persisted: after presence traffic, the drive's
  resource count and Loro snapshot bytes on both devices are unchanged
  (`/drive-usage`), and no `DbEvent` fires for presence.

Mirror the shipped two-session browser test from `presence-views.md`, but with
the two sessions on two *devices* over Iroh instead of two tabs on one hub.

## Open questions

- **OQ1 — Cursor bandwidth.** Document cursors move per keystroke. The source
  already throttles, but per-peer QUIC bandwidth for N devices wants measuring
  before shipping; may need coalescing the latest blob per (scope, channel)
  rather than sending every update (the `try_send`/drop-latest pattern in
  `send_live_update_wire_msg` partly covers this).
- **OQ2 — Which drives' presence to bridge.** Subscribe the bridge to presence
  for all synced drives eagerly, or lazily when a peer is live for that drive?
  Lazy matches the reconnect loop's drive set and avoids relaying presence for
  drives no peer shares. Leaning lazy.
- **OQ3 — Hub + peer at once.** A device with both a hub WS and a live peer
  would receive a collaborator's presence over WS and could leak it onto the
  peer link. Decision 8 says P2P presence is same-agent only, so the bridge must
  forward **only your own agent's** presence entries to peers, not every entry
  the hub relayed. Filter by `PresenceEntry.agent == our agent` on the outbound
  bridge.
- **OQ4 — Reservation vs. reuse.** Confirm `0x40` was reserved for exactly this
  and not some abandoned design with incompatible framing expectations before
  building on it (`protocol.rs:45` is a bare `const`).

## Carried over from the pairing field test (2026-09-04)

The field notes moved to [`completed/pairing-ux-field-test.md`](./completed/pairing-ux-field-test.md); the item below is the one still open that belongs here.

### M12 — Presence does not cross a peer link, because it was never wired (open)

> **Update 2026-09-03:** the wire is no longer missing. `EPHEMERAL (0x40)` has a
> codec, a peer send/receive path and a server bridge, with an Iroh e2e
> (`e2e_presence_crosses_the_link_without_being_stored`). What is still open is
> the two-device check on real hardware. The finding below is the original
> report and describes the pre-fix state.

Two machines syncing the same drive over Iroh still cannot see each other's
cursors. Not a regression: presence has no peer-to-peer path at all.

The tag exists and nothing uses it:

- `lib/src/sync/protocol.rs:45` — `pub const EPHEMERAL: u8 = 0x40;`
- `lib/src/sync/peer.rs` — **zero** references. Never sent, never handled.

Every working presence path is client-to-server WebSocket:
the cursor frame (then text `LORO_EPHEMERAL_UPDATE`, now `EPHEMERAL` of
kind `LORO`) in `lib/src/client/ws.rs` and
`server/src/handlers/web_sockets.rs`, fanned out by `CommitMonitor`
to the *subscribers of that server* (`commit_monitor.rs`,
"broadcast to all subscribers except the sender").

So presence is per-server. A browser on `atomic.ontola.io` and a desktop app on
`localhost:9883` are two islands: drive state flows between them over Iroh,
presence does not. Both users are "alone" while editing the same document.

**What wiring 0x40 involves.** Not much protocol — the shape already exists —
but presence is unlike everything else the peer link carries, and the
differences are the work:

1. **It must never touch the store.** Every existing peer frame ends in a write
   (`persist_update` / `add_resource_opts`). An `EPHEMERAL` frame must fan out
   and be dropped. Routing it through the same path would persist cursor
   positions into the CRDT and sync them forever.
2. **It is high-frequency.** Cursor movement is orders of magnitude noisier
   than commits. It needs its own budget and backpressure; the live channel is
   currently shared, and M9 showed what happens when that channel is saturated
   (the push loop lags and silently drops events, `RecvError::Lagged => continue`).
3. **Scope is per drive, and identity is per agent — not per node.** The
   WebSocket path fans out to subscribers of a subject. Across a peer link the
   sender is a node that may be relaying several agents' presence, so frames
   need to carry the originating agent and be filtered by drive readability on
   arrival, or one peer leaks who is editing what to a node that cannot read it.
4. **Echo suppression applies here too.** The same loop that produced M9's storm
   would apply at cursor frequency. The `source_id` mechanism added for
   M9 should carry over rather than be reinvented.
5. **It should degrade silently.** Presence failing must never affect drive
   sync — it is the least important thing on the link and should be the first
   dropped under load.

Worth doing: "why can't I see myself from my other machine" has no satisfying
answer today, and the reserved tag says someone already intended this.

## Fixed between 0.41.0-beta.2 (Jul 25) and 2026-08-15 — do not chase

Recorded because the first draft of this note treated them as live, and
someone reading the git history deserves to know they were resolved rather
than dropped.

- **The `unknown-drive` dead end.** On the July build, pairing from a node
  with no drive stopped at "Your workspace didn't arrive". Current code gets
  past that screen — but by provisioning a local drive rather than fetching
  the peer's, so the underlying problem is C0, not fixed.
- **"Paired with the device" reported as success while nothing synced.** The
  `count === undefined` branch (`PairingFlowProvider.tsx:280`) still exists
  and is still reachable. If shown, it should say plainly that no data
  moved.
- **The failure text sent people to a device that could not help** ("Open
  the app on your other device, then pair again"). Same story.
- **Second launch panicked** on an unwrapped redb open. Now handled — see C3
  for what remains.

## Unverified on a current build

- **"Connecting…" never resolving for a cross-origin server.** On the July
  build the desktop showed `atomic.ontola.io — Connecting…` indefinitely
  while the server logged successful upgrades (`/ws`, `101`); same-origin in
  a browser it showed `In sync`. Not re-tested after the rebuild.

## What this cost, and why

Roughly an afternoon went into diagnosing a deadlock that current code does
not have. The reasoning was sound and the evidence was real — logs, `file:line`
paths, a reproduction on a deliberately cleaned store — but it was
**source from the working tree explaining behaviour from a three-week-old
binary**, and the two had diverged. Every "confirmed" step made the wrong
conclusion feel firmer.

Two things would have caught it immediately:

1. **Check the binary's provenance before diagnosing from it.** The app was
   dated Jul 25; the tree had moved through PRs 1257 and 1260 and the vault
   work. That should have been the first question, not the last.
2. **Rebuild before writing findings up, not after.** The rebuild took ~15
   minutes and refuted the headline finding on the first try.

Worth keeping in mind for the Android app too, where the same "install an
old bundle, reason from current source" trap is one `adb install` away.
