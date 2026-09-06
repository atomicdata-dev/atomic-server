# Encrypted vault format (open spec)

> **Status:** v1 implemented in `lib/src/vault/` (2026-08-04). Phase 2 landed
> 2026-09-05: incremental per-lane cursors and checkpoints, described below.
> Compression, blob chunking and per-object signatures remain.
>
> Phase 2 changed two things a third-party implementation must know about:
> **pack format 2** (a lane pack may be a delta, so it is no longer
> self-sufficient on its own) and **zero-padded checkpoint numbers**. Both are
> written up in place rather than as an appendix.

This is the **format** half of Cloud Vault. The product plan and the hosted
control plane are internal to atomic-saas; the format is deliberately not,
because a blind backup you cannot independently verify or restore is a promise
rather than a property. Everything needed to write a third-party restore tool
is in this file and in `lib/src/vault/`.

## What the vault is

Encrypted, append-only backup of a drive's CRDT history, stored as opaque
objects. The party holding the objects can see how many objects exist, how big
they are, when they arrived and which device lane they belong to. It cannot see
subjects, property values, resource contents, resource counts, or file bytes.

Clients encrypt locally and talk to object storage directly via presigned URLs.
The hosted control plane brokers those URLs, quota and checkpoint publication;
object bytes never pass through it.

## Key hierarchy

```text
agent Ed25519 identity ──wraps──▶ DriveVaultKey (random 256-bit, per drive, epoch-numbered)
                                        │ BLAKE3 derive_key
                                        ├─▶ pack/envelope subkey
                                        ├─▶ blob-chunk subkey
                                        ├─▶ blob-id subkey (keyed hashing)
                                        └─▶ index/checkpoint-metadata subkey
```

Subkeys are `blake3::derive_key(context, drive_key)` with these exact context
strings — they are format, not implementation detail, and changing one changes
every subkey derived from it:

| Purpose | Context string |
| --- | --- |
| Pack / checkpoint | `atomic-vault 2026 pack envelope` |
| Blob chunk | `atomic-vault 2026 blob chunk` |
| Blob id | `atomic-vault 2026 blob id` |
| Index / checkpoint metadata | `atomic-vault 2026 index metadata` |

Notes that matter for anyone reimplementing this:

- **The agent key never encrypts bulk data.** Key rotation, drive sharing and
  multi-agent drives all depend on the wrapping key being separable from the
  data key. It *wraps* the `DriveVaultKey` — the KEK is
  `blake3::derive_key("atomic-vault 2026 agent secret wrapper", agent_secret)`,
  derived rather than used directly so the same bytes never both sign commits
  and decrypt backups.

  This is what lets a device be wiped and recovered with no extra secret:
  whatever restores the identity restores every drive key. Additional wrappers
  (a passkey PRF assertion, a generated recovery code) can be added to the same
  envelope later without re-encrypting anything, because what is wrapped is a
  32-byte DEK rather than the data.
- **Blob ids are keyed hashes**, `blake3::keyed_hash(blob_id_subkey, plaintext)`.
  Keyed rather than plain so two drives holding identical bytes produce
  different ids — a plain content hash would let the storage operator detect
  that two users hold the same file.
- **Blob ids derive from the drive key, not the epoch key**, so re-keying does
  not orphan every chunk already uploaded.
- **Epochs travel with the object**, never inferred. A key at epoch N refuses
  objects sealed at epoch N-1 rather than attempting them.

## Object envelope

Every stored object is `header ‖ nonce ‖ ciphertext+tag`.

| Field | Bytes | Notes |
| --- | --- | --- |
| version | 1 | Currently `1`. Unknown versions are refused, not partially parsed. |
| kind | 1 | `1` pack, `2` checkpoint, `3` index, `4` blob |
| key_epoch | 4 | big-endian |
| nonce | 24 | random per seal |
| ciphertext | rest | XChaCha20-Poly1305, includes the 16-byte tag |

**Cipher:** XChaCha20-Poly1305 over the subkey for `kind`'s purpose.
XChaCha rather than ChaCha because its 192-bit nonce is safe to draw at random
with no counter state. Vault objects are produced by several devices that never
coordinate, so any scheme requiring globally unique counters would be a
correctness hazard the first time two devices backed up at once.

**The 6-byte header is authenticated as AEAD associated data.** It is
cleartext, because the storage operator must be able to route and garbage-
collect objects without a key, but it cannot be altered: relabelling a pack as
an index makes the object fail to open rather than be reinterpreted under a
different subkey.

The header is deliberately dull. Everything in it is visible to the operator,
so anything identifying a resource, subject or count belongs in the ciphertext.

## Pack format

The plaintext inside a `kind = pack` object is MessagePack:

```rust
struct Pack {
    format: u8,            // 2; readers must still accept 1
    entries: Vec<PackEntry>,
    tombstones: Vec<String>,  // deleted subjects, pure_id() form
    coverage: BTreeMap<String, u32>, // checkpoints only; format 2
    observed: BTreeMap<String, u32>, // checkpoints only; format 2
}

struct PackEntry {
    subject: String,       // pure_id(), matching Tree::LoroSnapshots keys
    update: Vec<u8>,       // AtomicLoroDoc::export_updates_since output
}
```

**Format 2 means "not necessarily self-sufficient".** A format-1 pack carried
every resource's whole oplog, so any single one of them restored the drive. A
format-2 *lane* pack carries only what changed since that lane's cursor. A
reader that understands only format 1 must refuse these rather than import them,
because it also skips `Checkpoint` objects by kind before it decodes one — so it
would import the deltas, skip the anchor they hang off, and report a successful
restore of a drive missing most of itself. Refusing to parse is the loud
failure. Readers that do understand format 2 must still accept format 1: vaults
written before this exist and have to stay restorable.

`coverage` and `observed` are empty on a lane pack and meaningful only on a
checkpoint; see "Checkpoints" below.

Two invariants carry the design:

1. **Entries hold Loro *updates*, never snapshots.** Update size tracks edit
   size; snapshot size tracks document size. Backing up a one-word change must
   cost one word. A restore imports these with `import_update`.
2. **Tombstones travel with the updates they accompany.** A restore applying
   updates without them would resurrect deleted resources — a delete is data,
   not an absence of it.

   A deletion is detected by comparing the drive walk against what this lane
   backed up last time, held in each device's local `Db` and never uploaded
   (decision 2: incremental cursors are local, never shared metadata). Only
   subjects carrying a local tombstone are claimed: a subject that merely
   vanished could be a transient read failure, and an invented tombstone would
   *delete real data* on restore. A restorer applying a tombstone must remove
   the resource and its children, not merely record a marker — the marker alone
   leaves an earlier segment's oplog free to bring it back.

MessagePack rather than JSON because these are byte payloads, and base64ing
every CRDT update into JSON would inflate the one thing the format exists to
keep small.

Batching many resources into one object is also what hides resource counts:
the operator sees one object of some size, not a countable per-resource stream.

## Object layout

```text
vault/<drive-pseudonym>/
  lanes/<device-pubkey>/seg-000001.pack   ← append-only per device
  checkpoints/ckpt-000001.loro            ← self-sufficient anchor
  indexes/ckpt-000001.idx                 ← not yet written
  blobs/<keyed-hash>/<chunk>              ← not yet written
```

The drive pseudonym is a salted hash of the drive DID, computed by the control
plane; a self-hosted vault may use any stable string.

**Segment and checkpoint numbers are zero-padded to six digits** so lexical
listing order matches numeric order. Both S3 listing and filesystem traversal
sort lexically, and `seg-10` sorting before `seg-2` would replay history
backwards. The padding matters as much for checkpoints: `checkpoints/` sorts
before `lanes/`, so a listing hands a restore every checkpoint before any
segment, and `ckpt-10` ahead of `ckpt-2` would make it anchor on a stale view
of the drive.

**Each device appends only to its own lane.** No shared manifest, no
compare-and-swap, no merge-retry path. Concurrent backup from several devices
is correct by construction because Loro deduplicates ops by `(peerId, counter)`:
importing the same pack twice, or importing overlapping lanes in any order,
converges on the same state.

## Incremental export

A pass exports only what moved. Each device keeps, in its own local `Db` and
never in the vault, a **cursor**: subject → the Loro version vector this lane
has already shipped. A resource whose current version vector still equals its
cursor contributes nothing, and the check is a read of the stored blob's header
rather than a rebuild of the CRDT document, so an unchanged drive costs a header
read per resource and produces no object at all.

Measured on a native release build (`lib/tests/vault_incremental_cost.rs`):

| resources | full export | idle pass | one-resource edit |
| --- | --- | --- | --- |
| 100 | 137 KB / 19 ms | 0 B / 3 ms | 383 B / 4 ms |
| 500 | 675 KB / 113 ms | 0 B / 21 ms | 380 B / 25 ms |
| 2,000 | 2.69 MB / 508 ms | 0 B / 89 ms | 383 B / 93 ms |

Bytes per pass are flat in drive size; wall clock is still linear in it, at
roughly 45 µs per resource, because the walk visits every subject to read its
version vector.

Cursors are **local, never uploaded** — the metadata invariant is that no stored
object is O(resources). A device with no cursor (a fresh install, or one
upgrading from a format-1 vault) exports everything, which is always safe
because a full export is a superset of any delta. It is never safe to invent a
cursor for history that was never recorded as shipped.

## Checkpoints

A checkpoint is a pack sealed under `kind = 2` holding every resource's whole
oplog. It restores the drive on its own, and it is what lets the storage
operator delete the delta chain before it.

It carries two maps, and the split between them is load-bearing:

| Field | Claim | Used for |
| --- | --- | --- |
| `coverage` | "I provably hold every op in these lanes up to this segment" | Deleting. The control plane prunes covered segments. |
| `observed` | "These lanes were this long when I published" | Ordering. Decides which segments predate the anchor. |

A publisher may only claim coverage for lanes it can show it holds: its own,
which it wrote, and any it has imported. A lane it has merely seen listed is not
covered, however likely it is that the publisher synced those ops through a
node. The cost of being wrong is deleting the only copy of some history, so the
claim is deliberately conservative — with the consequence that a lane belonging
to a device that is gone for good is never pruned until some device restores
from it.

Checkpoint numbers are allocated by the client as `max(existing) + 1`. Two
devices over an anchorless vault will pick the same one; the control plane
rejects the second publication rather than letting two records claim different
coverage over one set of stored bytes, and the loser retries at the next number.

## Restore

```rust
import_vault_batch(store, key, vault, prefix, lane)
```

Reads the objects under `prefix`, opens them, decodes each pack, and merges each
entry into the store. Restore **merges rather than overwrites**, so running it
over a partially-synced device converges instead of clobbering local edits.

**Order is planned, not taken from the listing.** With no checkpoint present the
plan is "everything, in key order" — what a format-1 vault needs. With one, the
newest checkpoint is opened first (for its maps, not to apply it first) and the
timeline splits in three:

1. Segments at or below the anchor's `observed` mark that it does not `cover`.
2. The anchor.
3. Segments above the observed mark, and every segment of a lane the anchor
   never saw.

Segments the anchor covers are skipped entirely — they are also what the
operator deletes, so a restore must not need them.

Applying the anchor first instead would let an old segment from group 1 put back
a resource the anchor recorded as deleted. Applying it last would let it delete
a resource created after it. Loro makes the *updates* commute; tombstones are
applied by this code, so this code has to order them.

Restore imports with validation disabled. It replays history that was already
valid when written, and re-imposing today's required-property rules on old data
would make a schema change retroactively unrestorable — precisely when a backup
matters most.

## What this does not do yet

- **Indexes and blob chunking.** The `kind` byte already reserves their values;
  nothing writes them.
- **Per-object signatures.** Integrity today comes from the AEAD tag, which
  proves the object was sealed by someone holding the drive key. Signing
  objects with the agent key is a planned addition for provenance across
  multi-agent drives.
- **Compression.** Per-drive trained zstd dictionaries are Phase 2 and will
  apply before encryption (compress-then-encrypt, pack-level).

## Verifying this yourself

`lib/src/vault/` is the reference implementation, and its tests are written to
be readable as claims about the format:

- `a_wiped_store_is_restored_from_the_vault` — back up, discard the store
  entirely, restore into an empty one, compare materialized contents.
- `a_restore_without_the_right_key_fails` — the blind-vault claim.
- `sealed_packs_do_not_reveal_subjects` / `ciphertext_does_not_contain_the_plaintext`.
- `importing_the_same_pack_twice_is_idempotent`.
- `tampering_with_the_header_breaks_decryption`.
- `an_unchanged_drive_costs_nothing` / `one_edit_costs_one_edit` — the
  incremental claim, as bytes rather than as prose.
- `a_delta_chain_restores_the_drive` and
  `a_broken_delta_chain_loses_the_edits_in_the_missing_link` — the chain works,
  and what it costs when a link is missing. The second is why coverage exists.
- `the_newest_checkpoint_alone_restores_the_drive` — the self-sufficiency claim,
  moved from segments to checkpoints where Phase 2 put it.

Run them with `cargo test --features db-redb vault::`. No server, bucket or
network required — which is the point: a restore path that needs the vendor's
infrastructure is not an independent restore path.

## Related

- `encryption.md` — the broader E2EE exploration this specialises.
- `opfs-per-agent-encryption.md` — local encryption at rest, a different layer.
- `cloud-sync-managed-node.md` — the non-blind hosted tier above this one.
- The hosted control plane, quota model and product strategy live in
  atomic-saas `planning/CLOUD_VAULT_ARCHITECTURE.md` (internal).
