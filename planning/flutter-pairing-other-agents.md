# Pairing with someone else's device (different agents)

> **Status:** Proposal + hand-off (2026-10-21). Investigation done on the
> Flutter branch; the protocol work below belongs to whoever owns `lib/`
> (the "cloud" thread). The Flutter UI that consumes it is in place
> (`PairedDevice`, see "Dart side" at the end).

## What happened

Polle (his own agent) scanned Joep's pairing code on his phone and saw
"Paired with … / Sent 7 resources" (the screen shows "Paired with X" plus
`PeerSyncResult.describe()`). Joep's Devices list does not show Polle's phone,
and nothing shared moved either way.

Most likely sequence, with code references (line numbers as of `10e624cbc`):

1. **The Flutter code names only a node.** `PairScreen.formatQrValue`
   (`flutter/lib/screens/pair_screen.dart:192`) emits
   `atomic:node:<id>:<device name>`: no `drives=`, no `url=`, no agent, no
   one-time secret. A pairing code is routing only (`planning/device-pairing.md`).
2. **The scanner syncs its own active drive with the shower.** `_onDetect` →
   `_adoptDriveThenSync` (`pair_screen.dart:316`) adopts nothing because the
   code names no drive and Polle already has one; `_doSync` (`:338`) calls
   `peer_sync(node)` (`flutter/rust/src/api/simple.rs:1510`), which syncs
   **`store.get_active_drive()`**, i.e. Polle's own home drive. Only that one
   drive: none of Joep's drives shared with Polle are ever named.
3. **AUTH proves Polle's agent; Joep's device authenticates back.** Dial side
   `lib/src/sync/peer.rs:1783-1832` (AUTH signed over `drive#nodeId`), accept
   side `handle_stream` `:2736-2762`, auth-back `:2894-2917`, verified on the
   dial side at `:2125-2178`. Identity is real on both ends; nothing in it says
   "my device" vs "someone else's device".
4. **Joep's device asks for all of Polle's drive.** It has never stored it, so
   `handle_sync_vv_reconcile` (`lib/src/sync/engine.rs:1563-1612`) puts every
   subject in `pull` and deliberately leaves the list alone for an unknown drive
   ("`import_sync_push` bootstraps it").
5. **Polle's device serves it — everything, not what Joep may read.** On HELLO
   the dialer records the shower as a known peer (`peer.rs:1950`
   `add_known_peer_for_drive`). That makes it "paired", and
   `collect_readable_snapshots` (`engine.rs:2111-2166`, called with
   `Some(&remote_key)` at `peer.rs:1999-2004` and `:2083-2089`) then serves a
   paired peer **everything this node can read** (the replica rule from
   `350b56b2c`, meant for one person's own nodes that run their own node agent).
   So all 7 resources of Polle's private home drive went to Joep's phone:
   "Sent 7".
6. **Joep's phone stores them.** The accept side imports with Polle's identity
   (`engine.rs:1850` `admit_unknown_drive`); the Flutter store runs the default
   `OpenPolicy` (`lib/src/db.rs:1045-1050`, `policy.rs:122`), which lets any
   authenticated agent create a drive. Joep's agent cannot `check_read` them,
   but they are on his disk.
7. **Joep's device does not remember Polle.** Accept side, by design (F9):
   no `add_known_peer` on HELLO (`peer.rs:2716-2731`); `mark_known_peer_synced`
   only updates already-known peers (`:2479-2492`, `:2939`).
8. **Both go live.** Dial `peer.rs:2240`, accept `:2942`. While both are open,
   `start_live_sync` (`peer.rs:779-865`) streams the Loro delta of **every
   locally changed subject** to **every live peer** via
   `send_live_update_wire_msg_except` (`:667-721`), and `broadcast_ephemeral`
   (`:736`) does the same for edit ops/cursors, with no per-peer `check_read`.
   The receiver's admission gate (`admitted_for_drive`) usually stops the write,
   but the content has already crossed the wire.

To confirm on the devices: Polle's log has `Pushed 7 resources to peer`
(`peer.rs:2014`) or `… back to peer` (`:2098`); Joep's has
`enrolling new drive … for AgentSubject(<Polle>)` and
`import_sync_push: imported 7 resources for drive <Polle's drive>`.

## Answers

**(a) Symmetric?** No. Only the dialer (the scanner) records a `KnownPeer`
(`peer.rs:1950`; the doc comment on `is_paired_peer`, `:2319-2333`, says so).
The QR-showing side keeps the scanner only as a live connection
(`live_peer_ids`) until it disconnects. Its `getKnownPeers` (the Devices list's
source) never sees it.

**(b) Different agents: what is authorized?**
- Accept side (shower serving the scanner): per subject, `check_read` with the
  scanner's verified agent (`engine.rs:1495-1514`). Correct, but it runs only
  over the scanner's drive. The shower's shared drives are never offered.
- Dial side (scanner serving the shower's `pull`): `check_read` with the
  shower's agent, **or** with the scanner's own agent when the shower is a
  "paired" peer, which it is as soon as HELLO arrives. **This leaks the
  scanner's private data to another person's device.**
- Live mode: no read filter on outbound updates or ephemera. **Leak, both
  directions, for as long as both are open.**
- Writes: `import_sync_push` / `admitted_for_drive` check write rights, except
  `trust_owned` on the dial side and `OpenPolicy` bootstrap of unknown drives
  (any authenticated stranger can put a drive on a Flutter device).
- The handshake carries: AUTH (agent subject + signature over
  `drive#responderNodeId timestamp`), HELLO (display name + caps), auth-back
  AUTH (shower's agent over the scanner's node id). So each side **does** learn
  and verify the other's agent key. Nothing persists it, though: `KnownPeer` has
  no `agent` field.

**(c) Expected: both list each other and shared content syncs both ways.**
Not possible today: (a) one side forgets, (2) only the scanner's active drive
is synced, and (5)/(8) leak instead of share.

**(d) Why Polle is missing from Joep's Devices list.** The list is
`ServerSettingsSection` (`packages/atomic_flutter/lib/src/server_settings_section.dart:349-351`):
the known servers plus `backend.getKnownPeers()` (`get_known_peers_json`,
`simple.rs:1721`, i.e. the `KnownPeer` list in `Tree::PluginMeta`
`_iroh_known_peers_v2`). Live but unknown peers are not listed. Joep's device
never wrote Polle into that list (7).

## Proposal for `lib/` (cloud thread)

Ordered by urgency. 1 and 2 are confidentiality fixes and should not wait for
the rest.

### 1. Stop the paired-replica widening for other people's devices

`collect_readable_snapshots(…, paired_peer)` must widen only for a peer the
owner marked as **a replica of their own data**, never just because it is in
`known_peers`.

- `KnownPeer` gains `agent: Option<String>` (verified, from AUTH / auth-back)
  and `relation: Option<PeerRelation>`, where
  `enum PeerRelation { SameAgent, Replica, Contact }`.
- Widen only if `relation == Replica`. `SameAgent` needs no widening (the
  peer's own `check_read` already passes). `Contact` = rights only.
- Who sets `Replica`: an explicit choice. Pairing with an always-on device's
  code (has `url=`, or the remote's `/server` names this node id), "Connect by
  address", the server's `/iroh-sync`. A plain device code
  (`atomic:node:<id>:<name>`) whose auth-back agent differs from ours is
  `Contact`.
- Legacy entries (no `relation`): treat as `Replica` only if `agent` is unknown
  **and** the entry predates this change, and re-classify on the next
  connection, once auth-back has told us the agent: same as ours means
  `SameAgent`; otherwise keep `Replica` only for peers that look like servers
  (HELLO name `…atomic-server`, or `/server` match). Otherwise `Contact`.
  Polle's existing entry for Joep's phone then becomes `Contact`.
- Test: two stores, two agents. B dials A after a QR scan. A's private
  resource must not reach B, and B's private resource must not reach A
  (today it does). Same-agent pairing still syncs everything.
  `a_paired_replica_receives_what_the_owner_can_read` keeps passing with
  `Replica`.

### 2. Filter live mode per peer

`start_live_sync` / `broadcast_ephemeral` must send a subject's update only to
live peers whose verified agent may read it (`check_read`, or the owner's own
read for `Replica` peers). Cache verdicts per (peer, drive), as
`admitted_for_drive` does. Ephemera: gate on the drive or scope subject. Store
the peer's `ForAgent` in `LivePeer`; it is already known at `register_live_peer`.

### 3. Don't bootstrap a stranger's drive on a personal device

On a Flutter/Tauri device, `admit_unknown_drive` should admit only our own
agent, or a `Replica` / `SameAgent` peer. In practice that means `OwnerPolicy`
for personal stores, not `OpenPolicy`. Otherwise every scan of your code lets
the scanner park its drive on your phone.

### 4. The shower remembers the scanner (consented, not drive-by)

F9 is right that an unsolicited inbound connection must not get a
reconnect slot. A scan of a code I am showing is not unsolicited, so it needs
a signal:

- **One-time pairing token in the code.** `atomic:node:<id>:<name>?pt=<16 random bytes, b64url>`.
  The shower keeps it in memory while the pair screen is open (TTL about 10 min,
  single use per scanner). The scanner echoes it in HELLO as a new optional
  field (capability `pair-token`; old peers ignore it). The accept side checks
  it after AUTH succeeds. On a match it calls `add_known_peer_for_drive` with
  `agent` = the verified AUTH agent, `relation` = `SameAgent` or `Contact`, and
  `name` from HELLO. It also pushes a `SyncEvent { kind: "paired", remote, name,
  agent, received, sent }` so the shower's pair screen can say
  "Paired with Polle's phone · received 0, sent 3".
- Without the token (old scanners), fall back to a pairing window: an inbound
  AUTH while `pair_window_open()` is true counts, at the cost of a race
  with any other dialer in those minutes.
- New FFI: `open_pairing_code() -> String` (makes the token and returns the
  full code; replaces `formatQrValue`), `close_pairing_code()`.

### 5. Sync what the two people share, both ways

A `Contact` peer is useful only if the drives they share get synced:

- After AUTH, each side lists the drives the **other** agent may read. That
  means the drives in our store where `check_read(drive, their agent)` passes,
  plus their personal-drive `drives` list if public to them. Send it in a new
  `DRIVES` frame (or in HELLO as `drives: [...]`, capped).
- The dialer runs the existing per-drive reconcile for each drive in the
  intersection of "they offer" and "I want". "I want" means: I can read it and I
  hold it, or it is shared with me (a drive whose ACL names my agent).
  Each reconcile uses its own AUTH with `requestedSubject = drive#node`, since
  AUTH is bound to one drive (`peer.rs:2679-2700`). Alternatively, extend AUTH
  to bind a set.
- Record the drives in `KnownPeer.drives`. The auto-connect loop
  (`peer.rs` `start`, `:150-200`) should reconcile **those** drives for a
  `Contact` peer, not the active drive.
- The `PeerSyncReport` from `peer_sync` gets per-drive counts and the peer's
  agent: `{imported, pushed, in_sync, peer_name, peer_agent, relation, drives:
  [{drive, imported, pushed}]}`.

### 6. Who is the peer, as a person

Resolve `KnownPeer.agent` to a display name and picture via the normal
resource fetch: the agent resource is public by default. Store `agent_name`
alongside it (refresh when it changes) so the Devices list can say
"Polle · iPhone".

### Bridge (`flutter/rust/src/api/simple.rs`)

`get_known_peers_json` passes the new fields through unchanged (serde). New
calls: `open_pairing_code`, `close_pairing_code`, and `peer_sync_all(node_id)`
that syncs every shared drive with the peer (step 5).

## Dart side (done on the Flutter branch)

- `PairedDevice` (`packages/atomic_flutter/lib/src/paired_device.dart`) reads
  a `getKnownPeers()` row, including the fields above when present (`agent`,
  `agent_name`, `relation`, `last_sent`, `last_received`, `drives`). Unknown
  fields are tolerated, and absent ones fall back to today's behaviour.
- Devices list: a person icon and "Shared with you" for `contact` peers,
  "Your device" for `same_agent`. Tapping a peer card opens its details sheet:
  who it is, the node id (copy), last sync with counts, shared workspaces,
  "Sync now" (`AtomicSettingsBackend.syncPeer`) and "Forget this device".
- `AtomicClient.getKnownPeers` forwards the extra fields, so they light up
  without a Dart change once the host sends them.
- The pair screen titles the result with the name the other device introduced
  itself by (HELLO) when the code carried none: "Paired with <name>".

## Needs two real devices

- Two phones with **different** agents: after a scan, both list each other,
  nothing private crosses (inspect both stores), and shared drives sync both
  ways and keep syncing live.
- Same-agent phones: unchanged, full sync.
- Phone with an always-on server (own node agent): the replica still receives
  everything.
- Old scanner with a new shower, and the reverse: token absent, fallback.
