# Verifiable History

> **Status:** Building (2026-09-05). Decided in
> [`completed/commit-retention-floor-decision.md`](./completed/commit-retention-floor-decision.md)
> (option C, amended 2026-09-05). Companion to
> [`commit-retention-and-state-certificates.md`](./commit-retention-and-state-certificates.md)
> and [`authorization-sync.md`](./authorization-sync.md).
>
> Product goal: History is a list of **verifiable changes** — who, what,
> when, with cryptographic proof — for **every replica**, including a
> newly invited user. Same bar as `git clone` then `git log`.

## Goal

A new user who syncs a drive must be able to validate the log. Not only
the node that happened to see the live `COMMIT`. If they cannot, we have
not replaced what stored commits used to give.

Each History row:

| Shown | Source | Proof |
| --- | --- | --- |
| **What** | Loro checkout / diff | The oplog is the document |
| **When** | Envelope `createdAt` | Inside the signed JSON |
| **Who** | Envelope `signer` | Ed25519 over that JSON |
| **Proof** | Envelope `signature` | Same bytes `/commit` accepted |

## Split

```text
Loro oplog       = mergeable document (what, when, which peer typed)
Signed envelope  = commit object (who signed, when, proof)
Both             = replicate together
Graph / /commits = not a history store
```

Do not treat Loro change messages as “who.” They are plaintext. Do not
restore `/commits` as a queryable class. The log belongs to the resource,
like git objects belong to the repo, not to a site-wide commit collection.

## What is built (2026-09-05)

**Storage.** `Tree::Envelopes` (`lib/src/envelopes.rs`, all KV backends).
Key `pure_id ‖ 0x00 ‖ createdAt (u64 BE) ‖ 0x00 ‖ signature`, value the
commit JSON-AD exactly as `/commit` or the `COMMIT` frame accepted it. A
prefix scan on the pure id lists a resource's envelopes in time order. Not
a resource, not indexed: never in queries, `all_resources`, search or
collections, so nothing filters `did:ad:commit:` subjects by hand.

**Write.** `Db::apply_commit` queues the row in the same transaction as
the state it signs (`envelopes::record_ops`). Every signed commit, every
ingest path, one place. Critical commits (genesis, rights, parent,
destroy) additionally keep their `Tree::Resources` row as before, for
`AuthorizationProof` (P3) to find by `subject`. The destroy envelope that
#1370 put on the tombstone value is now just the subject's latest row;
`tombstones::destroy_envelope` reads it from there.

**Retention.** `EnvelopeRetention::{Latest, All}`, per node
(`Db::set_envelope_retention`, server `--envelope-retention` /
`ATOMIC_ENVELOPE_RETENTION`, default `latest`). `Latest` keeps the one
envelope that produced the current state, which is the floor (F6). `All`
keeps every envelope, which is the signed audit log (F7). Same write path;
the only difference is whether the prune of older rows runs.

**Binding to the oplog.** Every commit's Loro change carries a token in
its message: the browser's drain token, and since 2026-09-05 the Rust
builder path (`c-<time>-<rand>`) and `Commit::create_did` (the creator's
subject, as the browser writes it) do the same. History buckets versions
by that token; an envelope's `loroUpdate` names the tokens it introduced;
a version maps to its signer by lookup. A token is credited to the first
retained envelope that carried it (a Rust builder commit ships a full
snapshot), and the genesis carrier token is only ever credited to a
genesis envelope: the genesis is proven by the inline certificate (F1),
not by whoever later shipped a snapshot containing it.

**Verification.** `envelopes::attribute_history(store, subject)`:
signature check with the same code apply uses, tokens from a probe
import, `complete` = every tokened change in the stored oplog is claimed
by a verified envelope (the genesis carrier excepted, see above; untokened
server bookkeeping such as the `lastCommit` stamp is not counted). Anything
not covered is unattributed, never a guessed signer.

**Read.** Server `GET /history-attribution?subject=` (read-gated like the
resource; `server/src/handlers/history_attribution.rs`), WASM
`ClientDb.historyAttribution(subject)`, browser
`Store.getHistoryAttribution(subject)` merging both by signature.

**UI.** History's `VersionTitle` shows `by <agent> Verified` /
`Unverified` from the attribution, and `by peer … Unattributed` when no
envelope covers a version.

**Tests.** `lib/src/envelopes.rs` (retention, ordering, not-indexed,
attribution, tampering, two writers under both retentions, destroy fold),
`server/tests/it/history_attribution.rs` (signer, verified, read gate),
`browser/lib/src/history-attribution.test.ts` (parse, lookup, merge).

## Next

1. **Replicate the rows.** Live `COMMIT` already delivers the envelope;
   receivers persist it (they go through `apply_commit`). Bulk: a
   capability-gated side map in `SYNC_PUSH` / `SYNC_DIFF`, the shape
   `removeCommits` already uses, carrying the retained envelopes of each
   pushed subject; the receiver verifies before storing. Vault pack v2
   with an optional per-entry envelope list. A node on `latest` sends one,
   a node on `all` sends all. Until this lands a fresh device attributes
   only what it applied itself, and the hub answers the rest over
   `/history-attribution`.
2. **Secondary indexes** for "everything agent X signed" / "changes in
   drive D since T", as a second tree written in the same transaction,
   rights-filtered per resource on read. Not before a screen asks.
3. **Session certificates** (#1310): the envelope verify path is the one
   place a `sessionCert` chain is checked, with `notAfter` bounds and
   fall-back to Unattributed.
4. **Header-only envelopes** as a size win once bodies dominate storage.

## Resolved open questions

1. **Container shape.** Side tree, not a Loro container: an envelope
   inside the doc would sign a document that contains itself, and a
   snapshot import that ignored it would silently drop the log. The side
   tree costs one extra field on the wire (item 1 above), which is the
   price of proofs that cannot be confused with content.
2. **Who writes.** The node, after verify, in the apply transaction. Two
   replicas applying the same `COMMIT` write byte-identical rows under the
   same key.
3. **Concurrent edits.** Two envelopes, one merged document: both rows
   verified, diffs from Loro. Correct, like two git commits on diverging
   branches that later merge.
4. **Size / prune.** `latest` versus `all` per node. `latest` removes
   per-change verifiability for older versions, as a shallow clone does;
   it is the default because the floor is the current state.
5. **Verify in WASM.** Same signature check as apply; fail closed to
   Unattributed, never display a forged signer.

## What not to do

- Local-only blob table that live writes keep and clones never get
  (item 1 in *Next* is the fix, not optional).
- “Unattributed is fine for new users.”
- Re-index envelopes as Atomic resources / `/commits`.
- Put the agent DID in the Loro change message and call it proof.
- Require a linear `previousCommit` chain.
