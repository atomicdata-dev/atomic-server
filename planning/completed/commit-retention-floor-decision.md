# Commit retention floor

**Status:** Accepted 2026-09-01 — option C. Amended 2026-09-05 (see the end): `Tree::Envelopes` ships inside #1313 itself; #1274 is off the critical path.

> **Decision needed by maintainer**
>
> Question: what MUST a node keep of a signed commit after apply, so that authorization still verifies and audit still attributes — and can #1313 merge on that floor?
> Options: (A) keep the full commit log as today. (B) #1313 as proposed: drop content commits, keep only genesis/rights/parent/destroy rows. (C) envelope-on-resource: every resource keeps its latest signed envelope(s) in a side tree; the Loro oplog is the history; older envelopes are node-policy retention.
> Recommendation: **C** — authorization needs state, not a log; audit needs the signed bytes for the state you are looking at, which (B) throws away and (A) never replicates.
> Blocked PRs: #1313 (change), #1254 (rebase after #1313), #1274 (merge first).

## Context

**Storage today.** There is no commit tree. `enum Tree` in `lib/src/db/trees.rs`
has `Resources`, `LoroSnapshots`, `PropValSub`, `ValPropSub`, `QueryMembers`,
`WatchedQueries`, `PluginMeta`, `DriveMapping`, `DidMapping`, `Blobs` — nothing
commit-specific. A commit is stored as an ordinary resource row
`did:ad:commit:<sig>` in `Tree::Resources` (`lib/src/db.rs` `add_resource_tx`,
which keeps `loroUpdate` inside the blob only for commit subjects) and every
one of its atoms is indexed into `PropValSub`/`ValPropSub`
(`lib/src/db.rs` ~L3090: `add_resource_tx(&commit_resource)` + `add_atom_to_index`
per atom, unconditionally; same in `lib/src/storelike.rs` `apply_commit`). Commits
get no `LoroSnapshots` row (`db.rs` ~L2980). A `/commits` class collection is
populated (`lib/src/populate.rs` L226).

**Lookup today.** By subject (`get_resource("did:ad:commit:…")`) or by the
`subject` property index (`Query` on `urls::SUBJECT`). Rights on a commit row
are the rights of its target (`lib/src/hierarchy.rs` ~L270).

**What consults commits for authorization.** Nothing. `check_rights`
(`lib/src/hierarchy.rs`) reads `read`/`write`/`append` propvals on the
resource projection and walks `parent`. Creator identity comes from the inline
`genesis` certificate propval verified against the DID
(`lib/src/resources.rs` `genesis_signer`, `lib/src/genesis.rs`), not from the
genesis commit row; legacy resources minted before the cert (DID == commit
signature) are the exception. `validate_previous_commit` is off on every
production apply path (`lib/src/sync/engine.rs` `ingest_commit_json`,
`lib/src/sync/ws_apply.rs`). Destroy is remembered as a tombstone in
`Tree::PluginMeta` (`lib/src/sync/tombstones.rs`), not as a commit.

**What consults commits for audit/UI.** `browser/data-browser/src/components/CommitDetail.tsx`
fetches `lastCommit` to render signer/date (used by `ArticlePage.tsx`,
`ListView.tsx`, `ResourcePageDefault.tsx`). The History page does not: it
reads the Loro oplog (`browser/lib/src/resource.ts` `getLoroHistory` over
`doc.getAllChanges()`, `browser/data-browser/src/routes/History/useVersions.ts`)
and only uses the `lastCommit` propval of a version for a "Show Commit" link
(`HistoryDesktopView.tsx` L67–102). Server `/all-versions` and `/version` are
already Loro-backed (`server/src/plugins/versioning.rs`, `lib/src/history.rs`);
the "Phase 3" blocker in
[`commit-retention-and-state-certificates.md`](../commit-retention-and-state-certificates.md)
is stale. The oplog change message is a random drain token (`browser/lib/src/store.ts`
~L1438 `c-<random>`), so the oplog knows *what/when/peer-hex*, never *which agent*.

**What replicates commits.** Nothing. `SYNC_PUSH` entries are
`[subject][loro_bytes]` (`lib/src/sync/protocol.rs` `encode_sync_push`);
`UPDATE` carries a `commit_id` string, not the envelope (`decode_update`,
`flags::HAS_COMMIT_ID`); the drive walk skips commits by construction
(`lib/src/sync/engine.rs` `collect_drive_subjects`, BFS over `parent`). The
vault format stores **no commits**: `lib/src/vault/pack.rs` `PackEntry { subject, update }`
is `export_updates_since` bytes per drive subject plus tombstones
(`lib/src/vault/sync.rs` `export_vault_delta`); the encrypted-vault spec
([`encrypted-vault-format.md`](../encrypted-vault-format.md)) never mentions commits.
Only the live `COMMIT` frame (`0x13`, `[request_id][commit_json]`) moves an
envelope, and every receiver discards it after apply except the hub's own
`Tree::Resources` row. A device bootstrapped by bulk sync or vault restore has
zero envelopes today, under every option.

**The floor as written.** [`commit-retention-and-state-certificates.md`](../commit-retention-and-state-certificates.md)
"Required persistence": Loro snapshot/oplog, projection, tombstones, sync
metadata; genesis always retained. [`authorization-sync.md`](../authorization-sync.md)
§ "Relationship to node-level retention policy": the floor is genesis +
rights-changing (`read`/`write`/`append`) + parent-changing + destroy commits,
"regardless of node policy or class" — and § P2 notes retention is moot until
pruning exists. `hierarchy::AuthImpact::is_critical()` is that classifier,
already on `develop`. PR #1313's branch-only
`planning/auditability-loro-history.md` adds the product bar: History must be
verifiable on every replica ("`git clone` then `git log`"), so envelopes must
travel *with the resource*.

## The retention floor

Invariants per resource R. "Authz" = needed to decide or re-verify rights on
this node; "Audit" = needed to attribute a state to a signer.

| # | Invariant | Needed for | Argument (source) | Carrier today |
| --- | --- | --- | --- | --- |
| F1 | Genesis identity: the inline `genesis` cert (or, legacy, the genesis commit row) | Authz | DID = signature over the cert; creator = implicit writer (`authorization-sync.md` § implicit creator write; #1254 `agent_is_resource_creator`) | `genesis` propval in the Loro doc; `Tree::Resources` row for legacy DIDs |
| F2 | Current rights state: `read`/`write`/`append`/`parent` (+ `drive` stamp) in the projection | Authz | `check_rights` reads only this (`hierarchy.rs`) | `Tree::Resources` + `Tree::LoroSnapshots` |
| F3 | Grant-chain evidence: the signed commits that changed F2 (`AuthImpact::is_critical`) | Authz only for a **replica that does not trust its hub** (`authorization-sync.md` P3/P4, not built); Audit otherwise | Without them a granted replica cannot explain why signer S was allowed at time T | `Tree::Resources` rows, hub only |
| F4 | Destroy evidence: tombstone + signed destroy commit | Authz (anti-resurrection: tombstone); Audit (who destroyed: commit) | `is_tombstoned` gates `import_sync_push` (`tombstones.rs`); vault packs carry tombstones | `Tree::PluginMeta`; commit row |
| F5 | Loro oplog | Audit (history: what/when), sync causality | `getLoroHistory`, `history::versions`; oplog has no agent | `Tree::LoroSnapshots`, vault packs |
| F6 | Latest signed envelope for the current state of R | Audit (who signed what you see, offline-verifiable); echo-dedup needs only the id | `commit_monitor.rs` L242/L556 read `lastCommit` id; verification needs the bytes (`serialize_deterministically_json_ad` + signature, `lib/src/commit.rs` ~L1181) | `lastCommit` id only; bytes in the hub's commit row |
| F7 | Every past envelope of R | Audit (per-change attribution) | `commit-retention…md` "What `retention=none` costs" | `Tree::Resources` rows, hub only |

Authorization floor = F1 + F2 + F4-tombstone, plus F3 once grant-chain
verification ships. Audit floor = F6 at minimum; F7 is node/resource policy.
"Latest envelope per (resource, signer)" is not needed: rights are state (F2),
and a concurrent second writer's envelope becomes the previous one — keep it
under F7 policy, not the floor. `lastCommit` stays as a stamp; it does not
have to resolve to a resource.

## Options

| | (A) Full log (today) | (B) #1313 as proposed | (C) Envelope-on-resource |
| --- | --- | --- | --- |
| Rows per content commit | 1 resource row + ~7 index atoms (`db.rs` ~L3090) | 0 | 1 side-tree row, replaces the previous (F6); older rows per policy |
| Index/`all_resources` cost | Every commit ever signed is a `Tree::Resources` row scanned by `all_resources`/`build_index` | Critical commits only | None in `Tree::Resources`; critical commits as in (B) |
| F1–F4 (authz) | Yes | Yes (`is_critical` gate) | Yes (same gate) |
| F6 (who signed current state) | Hub only, via `did:ad:commit:` fetch | **Lost** — `lastCommit` points at nothing | Yes, on every replica that received it |
| F7 (per-change attribution) | Hub only | Lost | Policy (`recent`/`full` keep N rows per subject) |
| Bulk sync / vault / OPFS clone | No envelopes | No envelopes | Latest envelope travels with the snapshot |
| Wire change | None | None | `SYNC_PUSH` flag + optional entry field; pack format v2 |
| Verdict | Pays for a log nobody replicates or reads for rights | Correct authz floor; audit regresses to "Unattributed" everywhere and makes envelope-on-resource a second migration | Same authz floor; audit is a per-resource fact that syncs, not a class |

(A) also carries a real footgun: the audit log is indexed as ordinary data
(`ValPropSub` on `Value::LoroDoc`, which #1313 stops), so commits show up in
queries and have to be filtered out by hand (`browser/lib/src/collection.ts`
`did:ad:commit:` strippers, `useGetDriveStructure.ts`, `useTableAggregates.ts`).

(B) is a strict deletion. It is right that a commit is not a queryable class,
and its `is_critical()` gate is exactly F3/F4. But after it merges the only
node that ever held a content envelope drops it too, `CommitDetail` falls back
to `createdBy` (a forgeable propval, see `genesis_signer` doc comment), and the
follow-up doc on its own branch says the fix is to keep envelopes on the
resource. Merging (B) first means shipping the regression and then adding the
mechanism that (C) is.

## Recommendation

**C.** The rule: *a node must keep, per resource, the state the rights are
decided on and the latest signed envelope that produced it; everything older
is retention policy, and the Loro oplog — not commits — is the history.*

### Minimal mechanism

- **Where.** New `Tree::Envelopes` in `lib/src/db/trees.rs`, mapped to a
  table in `lib/src/db/redb_store.rs` (`table_def`) and the sled/btreemap/OPFS
  backends. Key: `pure_id ‖ 0x00 ‖ createdAt(u64 BE) ‖ 0x00 ‖ signature`.
  Prefix-scan on `pure_id` lists a resource's retained envelopes in time order;
  the last one is F6. Not a propval, not indexed, not a resource: it never
  appears in queries or `all_resources`, so nothing needs a `did:ad:commit:`
  filter. Critical commits (F3/F4) additionally keep their `Tree::Resources`
  row as #1313 does, so `AuthorizationProof` (P3) can still find them by
  `subject`.
- **What bytes.** The envelope is the signed JSON-AD exactly as `/commit` and
  `COMMIT` accepted it: `commit_resource.to_json_ad()` (`lib/src/commit.rs`
  `into_resource`), whose signature covers
  `serialize_deterministically_json_ad` (JCS, sorted keys, no `signature`, no
  `subject` for genesis). Verifying later = same code path as apply. v1 stores
  the full body including `loroUpdate`; a header-only form is a later size win.
- **Write.** One place: after `validate_and_build_response` in
  `Db::apply_commit` (`lib/src/db.rs` ~L3090) and `Storelike::apply_commit`
  (`storelike.rs` L288), in the same transaction as the snapshot write, then
  prune the prefix to `retention` (default `recent`: keep the last N, N≥1).
  `lastCommit` stamping (`commit.rs` ~L977) is unchanged.
- **Sync.** Live `COMMIT` (0x13) already delivers the envelope; the receiver
  persists instead of discarding. Bulk: add `sync_push_flags::WITH_ENVELOPES`
  (`lib/src/sync/protocol.rs` `encode_sync_push`/`decode_sync_push`); when set,
  each entry is `[subject][bytes_len u32][loro_bytes][env_len u32][envelope_json]`
  with `env_len = 0` for "none". Sender attaches F6 only. Receiver verifies
  the signature before storing (`Unattributed` on failure, never a forged
  signer). `UPDATE` keeps `commit_id`; it does not need the body. WS and Iroh
  share the encoder, so both transports get it at once.
- **Vault.** Bump `PACK_FORMAT` to 2 in `lib/src/vault/pack.rs` and add
  `PackEntry.envelope: Option<Vec<u8>>` (F6 only). A v1 pack restores as
  today with no envelopes; a v2 restore writes `Tree::Envelopes`. Older
  envelopes (F7) are excluded from the vault: they are node policy, and the
  vault's cost argument is "one word for a one-word change".
- **UI.** `CommitDetail` reads the local envelope via a `getLatestEnvelope`
  accessor (WASM + JS store) and shows Verified/Unattributed; History rows
  map a version's `lastCommit` id to a retained envelope when present.

### Sequencing

1. **#1274 first.** It collapses commit ingest to one entry point
   (`ingest_commit_json` + `CommitIngestOpts::{hub,peer,replica}` in
   `lib/src/sync/ingest.rs`; today `apply_commit` is called from
   `sync/engine.rs`, `sync/ws_apply.rs`, `wasm/src/lib.rs`,
   `flutter/rust/src/api/simple.rs`, `server/src/plugins/{chatroom,wasm}.rs`,
   `db.rs` bootstrap paths). Retention must be one policy applied at one
   gate; with six call sites it will drift.
2. **#1313 second, amended.** Keep its deletion (no content rows, no
   `/commits`, no `previousCommit`, no `LoroDoc` index keys) and its
   `is_critical` gate; add the `Tree::Envelopes` write and `SYNC_PUSH`
   `WITH_ENVELOPES`. Then the same PR that stops storing commits starts
   storing the F6 envelope — no window where attribution is gone.
3. **#1254 third.** Zones make effective write = `{genesis_signer} ∪
   explicit_write` and remove the auto-insert-into-`write` step. That is a
   change to F2 semantics and it relies on F1 (`genesis_signer`) — it must
   land on a store whose floor is already fixed, or the "what is auth
   evidence" question gets answered twice.
4. Then `authorization-sync.md` P3 (`AuthorizationProof` over F3 rows) and
   vault pack v2.

## Consequences for open PRs

- **#1313** — change: keep the deletion and the `is_critical()` gate; add
  `Tree::Envelopes` + the F6 write in both `apply_commit` bodies, the
  `SYNC_PUSH` `WITH_ENVELOPES` flag, and a `getLatestEnvelope` read for
  `CommitDetail`/History. Move `auditability-loro-history.md` (branch-only) onto `develop`
  with the side-tree decision recorded (its "prefer in-doc" open question 1–2
  is resolved: in-doc makes the envelope sign a doc that contains itself).
  Rebase after #1274.
- **#1274** — merge first, as is. Only requirement: the single ingest gate
  is where the retention write lands, so no new `apply_commit` call sites.
- **#1250** — merge as is; independent. Note that incremental `loroUpdate`
  (157 B vs ~6.5 KB) makes F6/F7 envelopes cheap to keep, which strengthens C.
- **#1254** — rebase after #1313. Its removal of auto-insert-into-`write` is
  consistent with F1/F2; its `check_append` fix touches F2 only. No commit
  dependency.
- **#1279** — merge as is; no commits needed. `lib/src/git_export.rs` skips
  `is_commit_did()` subjects and strips `lastCommit`/`previousCommit` from
  sidecars; its docstring already says it is "not a replica of Loro history,
  signed commits, or original DIDs". Git export is interchange, not audit.
- **`commit-retention-and-state-certificates.md`** — update after #1313:
  Phase 3 (versioning plugin on Loro) is shipped; "genesis commits always
  retained" becomes F1 (inline cert, legacy row); add F6 to "Required
  persistence".
- **`authorization-sync.md`** — P2 "retention class is moot until pruning
  exists" becomes true the day #1313 merges; the `Tree::Envelopes` prefix is
  the "subject → retained auth-commit ids" index it asks for.

Unverified: the exact per-commit index-atom count (depends on propvals
present); whether the browser OPFS DB stores commit rows via
`materializeCommitLocally` (browser side of F6 needs its own check).


## Amendment 2026-09-05

Built in #1313 (`lib/src/envelopes.rs`); this supersedes the *Minimal
mechanism* and *Sequencing* above where they differ.

- **Key is the same, retention is a knob.** Key
  `pure_id ‖ 0x00 ‖ createdAt ‖ 0x00 ‖ signature`. `EnvelopeRetention`
  is `latest` (one row, F6, the default) or `all` (every row, F7). No
  `recent N`, no per-class schedule: nothing reads a middle setting.
- **No #1274 gating.** The write sits in `Db::apply_commit`, which every
  ingest path already funnels through, in the apply transaction. Ingest
  consolidation is orthogonal and lands on its own schedule.
- **Binding to the oplog is explicit.** Every commit's Loro change carries
  a token (browser drain token; Rust builder and `create_did` now too).
  `attribute_history` maps envelope → tokens → History version, verifies
  signatures with the apply code, and reports `complete`. The genesis
  carrier token is credited only to a genesis envelope: F1 is the proof
  for creation, not whoever later shipped a snapshot.
- **Destroy evidence folds in.** The tombstone value is a marker again;
  the destroy envelope is the subject's latest row.
- **Read paths.** `GET /history-attribution`, WASM
  `historyAttribution`, `Store.getHistoryAttribution`; History shows
  Verified / Unverified / Unattributed.
- **Wire and vault carriage are the next PR**, as a `removeCommits`-style
  side map and pack v2 (see `auditability-loro-history.md` → *Next*).
  Until then a replica attributes what it applied itself and asks the
  hub for the rest.
- **Sequencing now:** #1313 (with envelopes) → #1274 → #1254.
