# Commits as State Certificates

> **Status:** Proposal (2026-05; per-resource retention added 2026-05-29).
>
> **Decision (accepted 2026-09-01):** the retention floor is envelope-on-resource
> ([`completed/commit-retention-floor-decision.md`](./completed/commit-retention-floor-decision.md));
> #1313 waits for `Tree::Envelopes`, sequence #1274 → #1313 → #1254.
> Reframes Atomic Commits around Loro as the resource history engine. It does
> **not** propose removing signed writes — it separates the *required trust
> boundary* (verify a signed write) from *optional audit retention* (keep the
> commit afterwards). Retention is resolved **per resource** (user-controlled,
> inherited down the parent chain), capped by node policy — see
> "Per-resource retention" below.
>
> **Shipped since:** ordinary content commits are discarded as resources
> after apply; the must-retain floor (`AuthImpact::is_critical`) stays. The
> signed envelope of every commit is kept per resource in `Tree::Envelopes`
> (`lib/src/envelopes.rs`): the latest one by default, every one under
> `--envelope-retention all`. History reads who signed which change from it
> (`/history-attribution`). Remaining: envelopes travel in bulk sync and the
> vault — [`auditability-loro-history.md`](./auditability-loro-history.md).
>
> **Current (2026-06-10 server, 2026-07-10 browser).** DID identity is no
> longer derived from the genesis *commit* signature. A `did:ad:` subject is
> the signature of a small inline binary **genesis certificate**
> (`create_did_with_cert`, `lib/src/genesis.rs`; browser `mintCertDid`) —
> shipped in `0b1b13b36` and `232aca8a0`, documented in
> [`genesis-self-verifying.md`](./genesis-self-verifying.md). The server
> still dual-accepts the legacy commit-signature form for existing subjects
> (`lib/src/commit.rs`, the `verify` fallback). Statements below that say the
> subject is derived from, or verified via, the genesis commit are superseded
> wording; "genesis commits are always retained" remains true as an audit
> property, not as an identity requirement.

## Thesis

Atomic keeps commits, but changes what they *mean*.

Today commits carry signed Loro updates, but the surrounding model still reads
as if the linear `previousCommit` chain is the canonical history of a resource.
That clashes with the Loro direction: the Loro document already holds the
mergeable, causal history. A linear commit chain is not the right source of
truth for conflict-free concurrent editing.

The cleaner split:

```text
Resource history   = Loro document / oplog
Write authority    = signed Commit
Commit retention   = node policy
```

A Commit is a **signed certificate authorizing a Loro state transition for one
resource**. It is required at the write/import boundary. A node does not have
to retain it forever as a resource once the resulting state is durable.

## Current tension

The system has already moved most state semantics to Loro:

- Property changes are encoded as `loroUpdate` bytes on the commit.
- Server apply imports the Loro bytes, materializes the current projection
  (`PropVals`), and stores a Loro snapshot.
- [`loro-source-of-truth.md`](./loro-source-of-truth.md) makes the Loro
  snapshot the canonical state for CRDT-backed resources.
- `loro.rs::get_history()` already reconstructs history by walking the Loro
  oplog's change ancestors — not the commit chain. (The older
  `server/src/plugins/versioning.rs` endpoints still replay stored commits to
  rebuild versions; Phase 3 retires them — see the Phase 0 findings.)

But commits still carry responsibilities that belong elsewhere:

| Responsibility | Belongs to |
| --- | --- |
| Mergeable resource history | Loro oplog |
| Causal ordering of edits | Loro (op IDs / version vectors) |
| Write authorization | Signed Commit |
| Proof of resulting state | Optional `stateHash` on the Commit |
| Audit feed (who changed what, when) | Optionally-retained Commits |
| DID genesis identity | Genesis Commit signature |

Signing is essential and stays. The problem is treating *retained commit
resources* as the canonical history store.

## Proposed definition

Replace:

> A Commit is a Resource that describes how a Resource must be updated.

With:

> A Commit is a signed certificate authorizing a Loro state transition for one
> Resource. The Resource's mergeable history lives in its Loro document;
> Commits provide verifiable authorship, authorization, and (optionally) a
> proof of the resulting state.

The public name "Commit" and the `/commit` endpoint / `COMMIT` frame stay
unchanged.

## Required versus optional

A conforming node **must** verify and apply signed commits. It **does not** have
to retain a commit after the resulting state is accepted and persisted.

**Required persistence:**

- Loro snapshot / oplog for each CRDT-backed resource.
- Derived current projection (`PropVals`) for reads, queries, and indexing.
- Tombstones for destroyed resources, keyed by resource identity.
- Sync metadata needed to compare causal state with peers.

**Optional persistence:**

- Commit resources themselves.
- Append-only audit logs and feed indexes derived from retained commits.

Normative shape for the spec:

```text
A conforming node MUST verify a Commit before applying a remote write.
A conforming node MUST persist the resulting resource state if the write is accepted.
A conforming node MAY persist the Commit as an audit resource.
Clients MUST NOT assume that historical Commit resources are retrievable.
```

## Idempotency: re-applying a commit is safe by construction

This is the load-bearing property that makes `retention=none` workable, so it
is spelled out before the wire format.

A node with `retention=none` keeps **no record that it applied a given
commit**. So it cannot answer "have I seen this commit?" by lookup. It does not
need to — **Loro provides idempotency directly**:

- Every Loro op has a unique ID `(peerId, counter)`.
- Importing an update whose ops are already in the doc is a **no-op**: Loro
  deduplicates by op ID.
- Therefore re-applying a commit to a doc that already contains its ops
  changes nothing, deterministically.

The apply path must treat this correctly. A re-applied commit produces **no
state change** — and that must be reported as **success** (return the commit
id), *not* an error.

This requires distinguishing two cases that look identical at the projection
level ("the commit produced no atom changes"):

1. **Idempotent replay** — the commit's ops are already in the Loro oplog.
   → Accept; it is already applied.
2. **Silent LWW loss** — the commit's ops are *new* but were authored against
   a doc that diverged from the server's, so they lose last-writer-wins and
   contribute nothing. → Reject; the client must refetch and retry.

The existing `validate_loro_causality` guard (`lib/src/commit.rs`) currently
conflates these — it rejects any commit that produced no atom changes. It must
instead check whether the commit's ops are already present in the doc's oplog
(case 1, accept) before treating an empty diff as loss (case 2, reject).

The browser outbox depends on this: on reconnect it may replay a commit the
server already applied over a different transport. With correct idempotency
that replay succeeds cleanly instead of stranding the outbox queue.

## Commit shape

The commit format does **not** need to change for this proposal. Today's
fields are sufficient:

```json
{
  "subject": "did:ad:...",
  "signer": "did:ad:agent:...",
  "createdAt": 1775504552928,
  "loroUpdate": "base64...",
  "previousCommit": "did:ad:commit:...",
  "destroy": false,
  "isGenesis": false,
  "signature": "base64..."
}
```

One **optional** field may be added later — a state proof:

| Field | Purpose |
| --- | --- |
| `stateHash` | Blake3 of the resource's materialized projection *after* this commit applies cleanly with no concurrent edits. Optional, signed when present. A diagnostic, not a gate — see below. |

What is **deliberately not** added:

- **No signed Loro frontiers / version vectors.** A Loro frontier is a set of
  `(peerId, counter)` pairs, and peer IDs are random per document. The client's
  doc and the server's doc for the same resource are different peer lineages,
  so "the same logical state" has *different* frontier bytes on each side.
  A signed `newFrontiers` the server is expected to reproduce and verify
  cannot work across peers. Frontiers/version vectors remain a **local,
  per-document** concern owned by the sync engine — never signed, never
  compared across peers as an identity. (Cross-peer frontier comparison is an
  open research item, not a dependency of this proposal.)
- **No `loroUpdateHash`.** The `loroUpdate` bytes are already covered by
  `signature`. A separate hash would only matter for content-addressed
  offloading of large updates — a distinct future concern, out of scope here.

### On `stateHash`

`stateHash` must be computed over the **canonical materialized projection** —
the resource's `PropVals` serialized as deterministic JSON-AD (sorted keys,
`loroUpdate` itself excluded) — **not** over Loro snapshot bytes. Loro
snapshots embed random peer IDs and are not byte-deterministic; hashing them
would produce a different hash on every node for identical state. The
deterministic-JSON-AD precedent already exists in
`commit.rs::serialize_deterministically_json_ad`.

`stateHash` is a **diagnostic**, not a validation gate. The signer computes it
over the state they *expect*. If a concurrent edit merged in between, the
server's materialized state legitimately differs and the hashes will not
match — that is correct CRDT behaviour, not an error. A mismatch means either
"a concurrent edit occurred" (expected) or "client and server materialized the
same Loro state differently" (a bug — the datatype-fidelity work in
`loro-source-of-truth.md` Phase 1 is what keeps materialization identical).
Treat a mismatch as a signal to log/investigate, never as a rejection.

### `previousCommit`

Demoted to optional audit/display metadata. It may stay for legacy chains and
human-readable history, but it is **not** a causal-validation gate — Loro op
IDs are the causal model. (This is already largely true in `commit.rs`, where
`previous_commit` is recorded as a propval but not validated.)

## Apply semantics

The authoritative apply path:

```text
parse Commit
verify signature over the canonical commit payload
check signer rights against current resource/drive policy
load the resource's current Loro document
import loroUpdate into the doc
  └─ ops already present  → idempotent replay: accept, no state change
  └─ ops new, empty diff  → silent LWW loss: reject, ask client to refetch
  └─ ops new, real diff   → normal apply
materialize the projection from the resulting doc
if stateHash present: recompute and compare (log on mismatch, do not reject)
persist Loro snapshot + projection + indexes  (one transaction)
persist a tombstone if destroy
persist the Commit only if node retention policy says so
emit node events
```

Invariants:

- Commit signature verification is **required** before any remote import.
- Commit *retention* is **not** required for future reads, sync, or history.
- The history UI reads the Loro oplog (the change list), not retained commits.
- `retention=none` must not break reads, writes, sync, history, search, or
  permissions — only the *audit feed* and *cryptographic authorship
  attribution per change* depend on retained commits (see below).

## What `retention=none` actually costs

Be honest about the tradeoff. The Loro oplog records, per change: *what*
properties changed, *when*, and *which peer*. It does **not** record the
*signed agent* — that lives only on the Commit.

So with `retention=none`:

- Resource history (the sequence of changes and time-travel) — **works**, from
  the Loro oplog.
- "Edited by «agent»" attribution per historical change — **lost**, unless the
  commit is retained.
- An append-only audit feed across resources — **unavailable**.

The current authorship of a resource is still knowable (the projection can
carry a "last editor" reference), but per-change attribution and audit feeds
genuinely require retained commits. Deployments that need those run `recent`
or `full`.

## Retention policy

Commit persistence is an explicit node-side policy:

```text
ATOMIC_COMMIT_RETENTION = none | recent | full
```

| Policy | Behaviour |
| --- | --- |
| `none` | Verify, apply, and discard the commit once the resulting state is durable. |
| `recent` | Keep a bounded, time- or count-limited cache for retry, diagnostics, and short-term feeds. |
| `full` | Keep every commit as an audit resource. |

Migration default: `full` (today's behaviour). Long-term default: `recent` —
it preserves recent-audit and diagnostics with bounded cost. `none` is for
storage-constrained or privacy-focused deployments that explicitly opt in.

**Genesis commits are always retained, regardless of policy.** A DID subject
is derived from its genesis commit's signature; verifying a resource's identity
requires the genesis commit's signed content. They are one per resource and
tiny — retaining them is cheap and non-negotiable.

**Cross-agent authorization extends the floor.** Once cross-agent grant-chain
verification is in scope (see
[`authorization-sync.md`](./authorization-sync.md)), the must-retain floor
expands beyond genesis to include rights-changing commits (`read` / `write` /
`append` / future group/capability), parent-changing commits, and destroy
commits — collectively, the *authorization-critical* commits needed to
explain why a given signer was allowed to write at a given point. A node
configured `retention=none` keeps this expanded floor, not only genesis.
Ordinary content commits remain discardable.

## Per-resource retention (user-controlled, inherited)

The node-level `ATOMIC_COMMIT_RETENTION` above is the deployment floor. But
retention is also a **product decision the user should make per resource** —
"keep full history of this contract" vs "this scratch note needs none." So the
effective policy for a resource is resolved, not global.

### Three lifetimes (only one is optional)

The clarifying frame: a resource is made of three things with three different
lifetimes, and **only the third is what retention controls.**

| Thing | Lifetime | Lives in |
| --- | --- | --- |
| **Current state** — the values right now | Always kept | Loro snapshot (current projection) |
| **Genesis facts** — `createdAt`, `createdBy` | Always kept | intrinsic propvals on the resource |
| **Change history** — everything between genesis and now | **Optional, per-resource** | retained commits / full Loro oplog |

Turning history off never costs the current data or the creation metadata.
That invariant is what makes a user-facing toggle safe: "stop keeping history"
can't be misread as "lose my resource" or "lose when it was made."

This makes denormalising `createdAt` (and `createdBy`) onto the resource a
**prerequisite**, not a nicety: a `retention=none` resource has no commit to
read those from, so they must be intrinsic propvals written at genesis. (It
also fixes today's fragility where views fetch a `did:ad:commit:<sig>` resource
just to render an author/timestamp — see "History / audit UI" below.)

### The `retention` property

A resource may carry a `retention` propval:

```text
retention = full | recent | none   (unset = inherit)
```

Effective retention resolves in order:

1. The resource's own `retention` propval, if set.
2. The nearest ancestor in the `parent` chain that sets `retention` (a folder
   or drive sets policy for its subtree).
3. The node default (`ATOMIC_COMMIT_RETENTION`).

So a user sets `full` once on a sensitive folder and everything under it
inherits it; a single ephemeral child can override to `none`. The node policy
is the floor a deployment can enforce (a storage-constrained node may *cap*
retention regardless of the resource's request — the resolved value is
`min(resource-or-inherited, node-max)`).

### Two orthogonal dials

Retention (*how much history*) is independent of signing granularity (*how
finely the kept history is attributable*). They compose:

| | `retention=none` | `retention=full`, batched sign (today) | `retention=full`, per-change sign (high-audit) |
| --- | --- | --- | --- |
| Current state | ✅ verifiable via state certificate | ✅ | ✅ |
| Per-save author/time | ❌ | ✅ | ✅ |
| Per-keystroke audit | ❌ | ❌ | ✅ (tamper-evident) |
| Storage cost | lowest | medium | highest (~150 B/change) |

Most resources want `none` or `recent`. Legal/regulated resources opt into
`full` + per-change signing. The per-change profile is specified in
[`sign-at-drain.md`](./sign-at-drain.md) ("high-audit profile"); it is not a
prerequisite for per-resource retention and can land later.

### Mechanism: Loro shallow snapshots

`retention=none` is not "throw away the resource" — it's "compact." Loro
supports a shallow snapshot at the current frontier plus GC of older ops. So:

- `full` → keep the full Loro snapshot + every signed commit/update.
- `recent` → shallow snapshot retaining a bounded window of recent history.
- `none` → shallow snapshot at the current frontier, drop prior ops and
  intermediate commits; the server issues a signed **state certificate**
  (the `stateHash`-bearing attestation defined above) so the compacted
  current state stays verifiable without the chain.

Compaction is a server-side background operation gated by the resolved policy;
the must-retain floor (genesis + authorization-critical commits) is never
compacted away.

## DID genesis

DID resource identity still derives from the genesis commit signature:

```text
did:ad:{signature-of-genesis-commit}
```

The genesis commit is the first signed certificate for a resource. For genesis
commits, `subject` is excluded from the signed bytes because the subject is
derived *from* the signature (circular otherwise). Genesis commits establish
identity and are always retained; this does not imply later commits must be.

## Relationship to Loro

| Loro owns | Commits own |
| --- | --- |
| Concurrent-edit causality and merge | Who authorized an import |
| Resource-local history (the oplog) | When the authorization happened |
| Time travel by version | Which resource was affected |
| Coalescing many local edits into one exported update | Which Loro transition was accepted |
| | Optional proof of the resulting state (`stateHash`) |

Commit granularity is free to vary — one property edit, a save boundary, a
batch of local edits, a sync boundary, a periodic checkpoint, a destroy. **One
commit is not assumed to equal one UI action or one Loro op.**

## Code impact

### `lib/src/commit.rs`

- Keep `Commit`; document it as a signed Loro-transition certificate.
- Split the `validate_loro_causality` guard into the two cases above:
  idempotent replay (ops already in the oplog → accept) vs. silent LWW loss
  (new ops, empty diff → reject).
- Add an optional `stateHash` field (computed/verified, never a gate).
- `previousCommit` stays compatibility/audit-only.
- Commits remain native signed resources, never CRDT-backed.

### `lib/src/loro.rs`

- Expose deterministic projection hashing for `stateHash` — over the
  materialized `PropVals` as canonical JSON-AD, never over snapshot bytes.
- Expose an "are these op IDs already in the oplog?" check for the idempotency
  branch of apply.

### `lib/src/db.rs` and apply paths

- Ensure accepted resource state is complete without any retained commit.
- Add `CommitRetentionPolicy` to the store/node config.
- Route commit storage through a single `maybe_store_commit` gate.
- Verify `get_resource`, sync import, query, history, and destroy never require
  a previous commit resource to exist.

### `server/src/handlers/commit.rs`

- Keep `/commit`.
- Return the accepted commit id/signature even when the commit resource is not
  retained.

### WebSocket protocol

- Keep `COMMIT` / `COMMIT_OK`.
- `COMMIT_OK` may include a retention hint (later protocol revision; not
  required for migration):

```json
{ "commit": "did:ad:commit:...", "subject": "did:ad:...", "retained": false }
```

### Browser and outbox

- The outbox stores signed commits as outbound certificates.
- A successful drain removes the outbox entry on acceptance, regardless of
  whether the server retained the commit — and an **idempotent-replay
  acceptance counts as success** (this is what unblocks the outbox after a
  same-commit retransmit).
- Client history reads the local Loro doc, never refetched commit resources.

### History / audit UI

History may be **absent by policy** (a `retention=none` resource has no commit
log and a shallow Loro snapshot with no past ops). The UI must treat that as a
first-class, non-error state — not a spinner, not an empty feed that looks like
a bug.

- **Basic facts** (author, creation time) come from **intrinsic propvals**
  (`createdAt`, `createdBy`) on the resource — never from fetching a
  `did:ad:commit:<sig>` resource. This is what makes them survive
  `retention=none`, and it removes the current fragile coupling (a chatroom
  message shouldn't fetch a commit just to show who/when).
- **Resource history page**: Loro oplog (change list + time travel) — available
  whenever the oplog is retained (`full` / `recent`); shows "history not
  retained for this resource" under `none`.
- **Audit/feed views** (per-change *signed* attribution): retained commits
  only, gated on policy + signing profile. Clearly indicate when unavailable.
- Distinguish three states explicitly: **current state** (always),
  **resource history** (retained-oplog-dependent), **signed audit log**
  (retained-commits + signing-profile-dependent).

### Required first step (prerequisite for any retention work)

Denormalise `createdAt` (and `createdBy` = genesis signer) as intrinsic
propvals written at genesis and carried in the Loro doc. Migrate every view
that reads creation/author from a fetched commit to read these instead. This
is independently shippable, fixes the current commit-fetch fragility, and is a
hard prerequisite for `retention=none` (which has no commit to read them from).

## Spec impact

Update `docs/src/commits/intro.md`, `commits/concepts.md`, `did.md`,
`websockets.md`, and `atomic-data-overview.md` (if it claims commits are the
history model):

- Define commits as signed state-transition certificates.
- State that commit retention is optional and node-policy-controlled.
- Demote `previousCommit` to optional audit metadata.
- Define the Loro oplog as the causal/history model for CRDT-backed resources;
  state explicitly that frontiers/version vectors are local sync state, not a
  cross-peer identity.
- Specify `stateHash` (canonical-projection hash) and that it is diagnostic.
- Clarify that a node may return an accepted commit id without making the
  commit resource retrievable later.

## Migration plan

### Phase 0 — audit assumptions

- [x] Find code that fetches or depends on historical commit resources.
- [x] Find code that treats `previousCommit` as required causal state.
- [x] Find tests that assume commits are persisted; separate
      resource-history tests from audit-retention tests.

**Findings (2026-05-23 audit).**

*Code that depends on retained commit resources:*

- **`server/src/plugins/versioning.rs` — the real blocker.** The
  `/all-versions` and `/version?commit=` endpoints reconstruct history by
  *replaying commits*: `get_commits_for_resource()` queries every commit with
  `Query::new_prop_val(SUBJECT, …)`, and `construct_version()` fetches a commit
  by URL and calls `commit.apply_changes()`. This legacy path **duplicates**
  `loro.rs::get_history()`, which already derives history from the Loro oplog
  with no commit dependency. Phase 3 must retire the commit-replay plugin in
  favour of the oplog path.
- **Commits are queryable resources** (`isA=Commit`): any commits collection or
  `Query` over commits depends on retention. This is the audit-feed surface the
  plan already scopes to `recent` / `full`.
- **Browser per-change attribution UI.** `data-browser` `CommitDetail.tsx` does
  `useResource(commitSubject)` to render signer + timestamp (chatroom, message,
  and resource pages); `lib/src/store.ts::materializeCommitLocally()` seeds that
  resource right after a post; `lib/src/websockets.ts::shouldFetchOnQueryUpdate`
  treats `did:ad:commit:` subjects as immutable-cacheable. All of this is the
  "edited by «agent»" feature the plan already says `retention=none` sacrifices.
- *Not* a blocker: `lib/src/hierarchy.rs` commit read-authorization fetches the
  *target* resource, not the commit resource.

*`previousCommit` as required causal state — confirmed NOT a blocker:*

- Rust `validate_previous_commit()` (`lib/src/commit.rs`) is opt-in via a bool
  flag that is **false** on the production apply path; it compares `lastCommit`
  equality and never walks a chain. `previousCommit` is audit/display metadata,
  exactly as this plan assumes.
- The browser only *builds* `previousCommit` chains. The chain token is
  `lastCommit`, a propval on the **resource projection** (always retained).
  `save()` / `destroy()` recovery re-fetches the *resource*, never the commit
  resource — so an unresolvable `did:ad:commit:` reference is harmless.

*Tests that assume commits are persisted (Phase 2 must gate, not delete, these):*

- Rust: `lib/src/commit.rs::agent_and_commit` (fetches the commit back via
  `get_resource`), and the `lib/src/db/test.rs` commits-collection-count test.
  Genesis-followup tests are fine — genesis is always retained.
- Browser: `commit.test.ts` "adds the just-posted commit to store.resources",
  `parse.test.ts` "keeps a commit resource as a commit", `websockets.test.ts`
  "still fetches unknown commit subjects".
- None of these exercise *resulting resource state* — they assert commit
  *retrievability* specifically. Phase 2's retention-disabled test mode must
  gate them on policy rather than remove them.

### Phase 1 — correct idempotency (do this first; unblocks the outbox)

- [ ] Split `validate_loro_causality` into idempotent-replay vs. LWW-loss.
- [ ] Accept idempotent replays as success end-to-end (server + outbox).
- [ ] Tests: replaying an applied commit succeeds; a divergent write is still
      rejected.

### Phase 2 — retention policy behind the current format

- [ ] Add `CommitRetentionPolicy`; default `full` (current behaviour).
- [ ] Route storage through `maybe_store_commit`.
- [ ] Add a test mode with retention disabled; ensure write/read/sync/history
      all pass with it off (genesis commits still retained).

### Phase 2.5 — intrinsic creation metadata (prerequisite for per-resource)

- [ ] Write `createdAt` (+ `createdBy` = genesis signer) as intrinsic propvals
      at genesis, carried in the Loro doc.
- [ ] Migrate views that read creation/author from a fetched
      `did:ad:commit:` resource to read these propvals instead.
- [ ] Independently shippable; also fixes the current commit-fetch fragility
      (chatroom `<CommitDetail>` vanishing on refresh).

### Phase 2.6 — per-resource retention resolution

- [ ] Add the `retention` propval (`full | recent | none`, unset = inherit).
- [ ] Resolve effective policy: resource → ancestor `parent` chain → node
      default, capped by node max.
- [ ] Loro shallow-snapshot + GC compaction for `none` / `recent`; issue a
      signed state certificate on compaction.
- [ ] UI: a `retention` control on the resource (and folder/drive for
      subtree default).

### Phase 3 — Loro-based history

- [ ] Retire `server/src/plugins/versioning.rs` (the commit-replay
      `/all-versions` and `/version` endpoints) in favour of
      `loro.rs::get_history()`, which already derives versions from the oplog.
- [ ] Move the history UI/API onto the Loro oplog.
- [ ] Keep audit/feed UI explicitly backed by retained commits, surfacing when
      retention is unavailable; treat "history not retained" as a first-class
      state.

### Phase 4 — optional `stateHash`

- [ ] Compute `stateHash` over the canonical projection on sign.
- [ ] Recompute and compare on apply; log mismatches, never reject.
- [ ] Keep accepting commits without it.

### Phase 5 — shift the default

- [ ] Default retention → `recent`; keep `full` available for audit
      deployments and `none` for opt-in minimal storage.
- [ ] Conformance tests asserting retained commits are optional.

This proposal depends on [`loro-source-of-truth.md`](./loro-source-of-truth.md)
being substantially complete — Loro must be the canonical, faithfully
materialized state before commit retention can safely become optional.

## Open questions

1. **Retention scope.** ~~Per-node, per-drive, or per-resource?~~ **Resolved
   (2026-05-29): per-resource, inherited.** Effective policy =
   `min(resource-or-inherited-ancestor, node-max)`, where the inherited value
   walks the `parent` chain (resource → folder → drive) and falls back to the
   node default. See "Per-resource retention" above.
   [`authorization-sync.md`](./authorization-sync.md#per-class-retention-preferences)
   adds a **per-class** preference declared in the ontology — orthogonal, and
   composes as a hint when a resource sets no explicit `retention`. The
   cross-agent authorization-critical floor (genesis + rights-changing +
   parent-changing + destroy) still wins over all of them. See
   [`authorization-sync.md` § Relationship to node-level retention policy](./authorization-sync.md#relationship-to-node-level-retention-policy).
2. Do audit feeds need a bounded mode with periodic signed checkpoints, so a
   feed survives `recent` eviction without keeping every commit?
3. How should a node advertise its retention policy to clients and peers?

## Related plans

| Doc | Relationship |
| --- | --- |
| [`loro-source-of-truth.md`](./loro-source-of-truth.md) | Makes Loro the canonical CRDT resource state — a prerequisite. |
| [`unified-sync.md`](./unified-sync.md) | Uses signed commits at the outbox/transport boundary. |
| [`sync.md`](./sync.md) | Current WS `COMMIT` implementation and echo suppression. |
| [`atomic-lib-runtime.md`](./atomic-lib-runtime.md) | Future node boundary where retention becomes runtime policy. |
| [`unified-data-layer.md`](./unified-data-layer.md) | Browser outbox must not assume retained commit resources. |
