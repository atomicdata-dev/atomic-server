# Scalable drive reconciliation & signed state roots

> **Status:** Follow-up design; the stateless RBSR implementation was removed
> in September 2026. Its Rust and TypeScript modules no longer exist. Current
> WebSocket reconnects use a hash-first probe, then send the full per-resource
> version-vector inventory on `SYNC_RESEND`. `RBSR_FP` returns `unsupported`;
> `RBSR_ITEMS` remains an inventory operation. Sparse v2 version vectors and
> their canonical SHA-256 hash are implemented and pinned across Rust and TS.
> An incrementally maintained range-fingerprint index and signed state roots
> remain proposals below, not deployed protocol behavior. See the current
> [wire reference](../docs/src/websockets.md#drive-synchronization-over-websocket).
> Ties the reconciliation redesign to the signed-state-certificate direction in
> [`genesis-self-verifying.md`](./genesis-self-verifying.md),
> [`commit-retention-and-state-certificates.md`](./commit-retention-and-state-certificates.md),
> and F1 in [`unified-sync.md`](./unified-sync.md).

## The problem

The `SYNC` reconcile compares a **flat, whole-drive hash** over every
subject's Loro version vector. That hash is a degenerate 1-level Merkle tree:
one root over all leaves. Consequences:

- **Cost tracks the drive, not the change.** One changed resource flips the
  drive hash, forcing an exchange/diff over the drive's whole VV set to locate
  the single delta. This is O(drive), not O(divergence).
- **Future fingerprints must preserve cross-language agreement.** The current
  sparse v2 hash has a defined SHA-256 encoding and a shared Rust/TS golden
  vector. A range index must preserve that agreement under updates. Signing a
  materialized-content root still needs its own canonicalization contract; the
  existing version-vector hash does not prove document content (see
  [`genesis-self-verifying.md`](./genesis-self-verifying.md) § `stateHash`).

The goal: reconciliation whose cost scales with the **delta**, and — as an
additive step — a **signed drive state root** that also closes F1 (unsigned
Layer-2 state transfer) and enables offline drive verification.

## Foundation already landed

These are stateless wins that reduce the constant factors and set up the
structure work; they are NOT the redesign:

- **Drive-scoped VV read** (`afbf8d99`): the client reads VVs for only the
  target drive (parent-index walk via `collect_drive_subjects`), O(this drive)
  instead of O(entire local DB).
- **Hash-first probe** (`236025e1`, binary `SYNC` with `"probe": true` since
  2026-09-04): reconnect sends only the drive hash; the
  server answers `SYNC_OK` or `SYNC_RESEND`. The full VV crosses the wire only
  on a mismatch. This is the natural hook the structure plugs into: the probe
  becomes "compare root fingerprint," and a mismatch triggers a **range/subtree
  descent** instead of a full resend.
- **Sparse v2 inventory and hash** (`bedede432`): each resource lists only its
  non-zero peer counters. `compute_drive_hash_v2` and `canonicalDriveHashV2`
  hash byte-ordered subjects and peers with SHA-256; a shared golden vector
  checks agreement. This removes the dense resources-times-peers expansion,
  while mismatch discovery still compares the drive's resource inventory.

The first stateless RBSR attempt recomputed the whole drive inventory during
each range round trip and cost more than a full comparison. It was removed in
`1d7f312a6`. A new implementation needs the maintained fingerprint structure
described below rather than restoring that descent unchanged.

## Structure decision: RBSR over a domain-hierarchy Merkle

A Merkle tree mirroring the `parent` hierarchy is tempting (the tree is free —
`collect_drive_subjects` already walks it) and works well for **bushy** drives.
But it degrades to O(children) on a **wide, flat, hot** node — and those are
common and exactly the churny case: Comments / messages / activity feeds are
inherently flat and high-write. A pure hierarchy Merkle bets the reconcile cost
on the hierarchy being balanced, which it often isn't.

**Decision: lean on range-based set reconciliation (RBSR), distribution-agnostic
over the sorted subject keyspace, using the hierarchy at most as a coarse
first-level split.** RBSR bisects a key range, exchanges one fingerprint per
half, prunes matching halves, and recurses into differing ones — a flat folder
of 10k comments is just a contiguous range it splits logarithmically. It handles
bushy and flat uniformly.

**Reference, not adoption.** iroh 0.35 (our pin) ships core transport only; no
RBSR crate is in the tree. `iroh-willow` is unreleased. `iroh-docs` is the
maintained RBSR implementation and the reference to study — but its data model
(multi-dimensional signed key-value *entries* with author keys) doesn't map onto
Atomic resources, so take the **algorithm + fingerprint tree**, not the crate.
Meyer's range-based set reconciliation paper is the primary source.

**RBSR does not escape incremental maintenance.** To compute a range fingerprint
in O(log n) you need a balanced monoid/Merkle tree over the sorted keyspace,
maintained on every write. That is the same "update the structure on write, or
silently diverge" problem as a server hash cache — a stale interior fingerprint
that happens to match the peer's causes a wrong prune and a **missed update**.
The adversarial test ("a write between structure-update and reconcile is never
reported as in sync") is the centerpiece of any implementation, exactly as it
would be for the deferred hash cache.

**Tradeoff accepted:** RBSR is interactive (several round-trips to converge) vs
today's one-shot exchange. Acceptable over a live WS/QUIC session; the hash-first
probe still short-circuits the common in-sync reconnect to a single round trip.

## Leaf decision: version vectors first, content later

What the leaves hash determines both the cross-language cost and whether a signed
root also proves content:

- **VV leaves (start here).** Reuses the VV hashing that already works
  cross-language (the current fast path fires). Cheap, additive, gets the
  reconciliation win now. A VV root proves *"these versions,"* not *"this
  content"* — a verifier still needs the ops to confirm state. Good enough for
  reconciliation and a weak provenance signal.
- **Content leaves (later, gated).** Hashing the canonical materialized
  projection (the reserved genesis `stateHash`: Blake3 of sorted-key JSON-AD,
  `loroUpdate` excluded) makes a root **content-binding** — like AT Protocol's
  MST over record CIDs — so a peer can verify a whole drive offline from one
  signature. This re-triggers the exact cross-language canonicalization the team
  deferred, so it is gated on that work (below).

## The real project: one canonical cross-impl hash

The through-line behind all of this: the deferred genesis `stateHash`, the latent
flat-hash sort bug, and any content-binding signed root all need **one spec'd
canonical hash that TS and Rust produce byte-identically.** Doing it once, for
VVs first and the materialized projection later, unblocks everything and kills
the dual-implementation drift. Treat this as the load-bearing task, not a detail.

## Signed state root (the additive payoff)

A maintained drive root can be **signed** by the drive agent → a *drive state
certificate*. What that buys, beyond efficient reconcile:

- **Closes F1.** Layer-2 (`SYNC_PUSH`) currently transfers unsigned raw state.
  A signed root gives the reconcile provenance — the state-first-wire direction
  in [`unified-sync.md`](./unified-sync.md).
- **`retention=none` can prove drive state** without keeping commits
  ([`commit-retention-and-state-certificates.md`](./commit-retention-and-state-certificates.md)).
- **Offline whole-drive verification** from a single signature.
- **Reuses the genesis `stateHash` as the leaf** — the per-resource content hash
  already reserved in the cert becomes the Merkle leaf, so the content-hash
  investment pays off twice.

**Wrinkle:** the root moves on every write, so "sign the root" means re-signing
per commit (or per batch). Same-agent drive: the owner signs, clean. Multi-writer
drive: the root attests *state*, not *single authorship* — it complements
per-commit certs, it doesn't replace them.

## Phasing

1. **Preserve the canonical hash contract** (foundation implemented). Sparse
   v2 already defines subject/peer ordering, counter encoding, and SHA-256,
   with a shared Rust/TS vector. A new range-fingerprint format needs equally
   explicit versioning and cross-implementation fixtures.
2. **RBSR over VV leaves.** Fingerprint tree over the sorted keyspace, maintained
   on write; range-exchange protocol behind the hash-first probe (probe = root
   fingerprint; mismatch = range descent, not full resend). Adversarial
   stale-node test as the acceptance gate. Measure against real drive shapes.
3. **Content-hash canonicalization.** Extend the canonical hash to the
   materialized projection; populate the genesis `stateHash` (additive, reserved
   flag already exists).
4. **Signed state root.** Sign the (content or VV) root as a drive state
   certificate; carry it in the reconcile to close F1; wire `retention=none`
   drive-state proofs.

Phases 1–2 deliver the efficiency win alone. 3–4 are the provenance/verification
payoff and are independently deferrable.

## Open questions

1. **Root over VVs or content, for the *signed* root?** Signing the VV root is
   cheap but not content-binding; the content root proves state but needs Phase 3.
   Can start signing the VV root in Phase 2 and upgrade.
2. **Fingerprint-tree home.** Server-side (both transports benefit; needs the
   write-path maintenance hook), client-side (OPFS), or both. The maintenance
   hook is the scattered-write-surface risk flagged for the hash cache.
3. **Multi-writer signed roots.** Who signs, how often (per commit vs batched vs
   periodic checkpoint), and how a verifier interprets a root signed by one of
   several drive writers.
4. **Re-implement RBSR vs. thin-wrap `iroh-docs` internals.** Algorithm is small;
   the fingerprint-tree + wire framing is the bulk. Decide before Phase 2.
