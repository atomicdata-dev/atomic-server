# Query & Index Performance

> **Status:** Design adopted + first tranche implemented (2026-07-24).
> Started as a diagnosis after a comparative benchmark against NextGraph
> surfaced collection queries as disproportionately slow (~100µs of server
> work *per matching resource*). The root causes are understood and verified
> (see Findings below); this doc now also records the **target architecture**
> for the index/query layer and tracks which pieces are built.
> Related: [`zones.md`](./zones.md) (structural authorization fix),
> [`disk-storage-and-persistence-optimization.md`](./disk-storage-and-persistence-optimization.md)
> (write-path counterpart), [`authorization-sync.md`](./authorization-sync.md).

## Target architecture

**Loro for authoritative state, materialized rows for reads, generic indexes
for candidate selection, and an intersection-based planner for query
execution.**

Loro stays the canonical merge/history representation. Everything queryable is
a derived, rebuildable projection:

1. **Materialized rows** — `Tree::Resources` (subject → msgpack `PropVals`)
   *is already exactly this*: every write path persists the propvals
   materialized from the merged Loro doc, in the same transaction as (or
   immediately after) the snapshot write. The read/query layer just wasn't
   using it (`get_resource_shallow` existed, unused). Queries must never
   decode a Loro snapshot; they read rows.
   The one wire requirement that seemed to force full materialization —
   clients seed their editing LoroDoc from a `loroUpdate` propval on each
   member — does **not** require a decode: the raw snapshot bytes from
   `Tree::LoroSnapshots` are attached verbatim as the `loroUpdate` value.
   Row + raw bytes reproduce the exact response the old decode path built.
2. **Generic indexes** — `PropValSub` / `ValPropSub` remain the candidate
   selectors. Their sort segments (and `QueryMembers`') move to an
   **order-preserving typed encoding** (tag byte + memcomparable payload:
   null < bool < f64-keyed numbers/timestamps < case-folded strings) so
   numeric/date ordering is correct at the byte level (fixes #287) and range
   operators can execute as index range scans.
3. **Materialized query results** — `Tree::QueryMembers` holds sorted member
   sets only for *watched* (live-subscribed or reused) filters. Its keys are
   `query_id(16B blake3 of the canonical filter encoding) || typed sort key
   || 0x00 0x00 || subject` instead of embedding the full serialized filter
   per entry.
4. **Planner** — multi-constraint (AND) queries pick the most selective
   constraint via bounded index-prefix counting (scan-capped cardinality
   estimate), iterate that candidate set, and verify remaining constraints
   against materialized rows. Intersection of candidate subject sets, not
   N full materializations.
5. **Live-query routing** — the in-memory watched-filter registry is keyed
   by `(drive, property)`, so a changed atom only evaluates filters that
   reference that property (or value-only filters), not every filter in the
   drive.
6. **Authorization on rows** — `check_rights` reads only propvals, so it
   runs on shallow rows; a per-query memo caches per-subject outcomes so an
   N-member listing does one ancestor walk, not N. (The zones index in
   [`zones.md`](./zones.md) remains the structural end-state; the memo is the
   architecture-compatible stopgap.)
7. **Counts** — exact `totalMembers` still requires walking the full index
   range (entries are cheap to walk now, but it's still O(matches)). The
   planned next step is cursor pagination + `hasMore` on the wire, replacing
   exact counts for large sets. Not built; needs `@tomic/lib` API changes.

### Implementation status

| Piece | Status |
| --- | --- |
| Shallow-row reads in `query_basic` / `query_sorted_indexed` (no Loro decode per member; raw-snapshot `loroUpdate` attach for nested bodies; subjects-only skips bodies) | **built (this pass)** |
| Per-query rights memo (`hierarchy::RightsCache`) | **built (this pass)** |
| Typed order-preserving sort keys in `QueryMembers` (+ correct numeric sort, #287) | **built (this pass)** |
| Compact `query_id` keys in `QueryMembers` + id-keyed live `QUERY_UPDATE` routing | **built (this pass)** |
| `(drive, property)`-routed watched-filter matching | **built (this pass)** |
| Most-selective-constraint planner for AND filters (bounded cardinality estimates) | **built (this pass)** |
| Typed sort keys in `PropValSub`/`ValPropSub` sort segment | not built (their sort segment is currently unused by ordering-sensitive paths) |
| Cursor pagination / `hasMore` instead of exact counts | not built (wire + client change) |
| Batched KV reads (one read txn per query) | not built (`KvStore` trait change; per-`get` redb txns remain) |
| Zones index (walk-free auth) | see [`zones.md`](./zones.md) |
| Memoized ancestor *fetch* in the rights walk (consult the memo by subject before `get_parent`; ancestors loaded via `get_resource_shallow`) | **built** — see [`slow-collection-queries.md`](./slow-collection-queries.md) |
| Cap on the auth-denied member cascade (stop `resolve_query_member` after `AUTH_DENY_STREAK_CAP` consecutive denials while filling a page) | **built** — see [`slow-collection-queries.md`](./slow-collection-queries.md) |

## Benchmark context

An external comparative benchmark (`@tomic/lib` vs. the NextGraph JS SDK,
1000 resources, create/edit/history-traversal/query, both against local
servers) flagged the asymmetry: a single query fetching all 1000 members of a
collection took ~130–160ms, vs. ~6ms for NextGraph's equivalent SPARQL query.
Caveat: NextGraph's data model is per-document CRDT branches, not one global
store — not apples-to-apples — but the absolute cost on the atomic-server
side was real and independently reproducible.

Criterion benchmarks live at `lib/benches/lifecycle_bench.rs`
(`cargo bench -p atomic_lib --bench lifecycle_bench --features db-redb`).

## Findings (history)

### Finding 1 — vector search indexed every write by default (fixed)

Semantic search (fastembed/ONNX + LanceDB) ran on every commit. Now opt-in
via `--enable-vector-index` / `ATOMIC_ENABLE_VECTOR_INDEX` (default off).
See `server/src/config.rs`, `server/src/vector_search/enabled.rs`,
`server/src/serve.rs`.

### Finding 2 — redundant Loro snapshot re-export on every read (fixed)

`Db::get_resource()` imported a snapshot then unconditionally re-exported it.
Fix: `apply_state_doc_with_snapshot` reuses the bytes in hand
(`lib/src/resources.rs`, `lib/src/db.rs`). Verified paired impact: edit −11%,
history −12%, 1000-member query −7.7% (142.2ms → 131.2ms).

### Finding 3 — collection queries fully materialized every match (fixed this pass)

`query_basic` / `query_sorted_indexed` called `get_resource_extended` — a
full Loro decode + permission walk + extender scan — per member, per query,
even for subjects-only requests. Empirically ~100µs/member, linear in match
count; pagination was a minor factor (~15–20ms of the ~130ms).

The blocker for using `get_resource_shallow` was confirming that
`Tree::Resources` and `Tree::LoroSnapshots` stay in sync on every write path.
**Audited 2026-07-24 — the invariant holds:**

- `apply_commit`: `resource_new`'s propvals are materialized from the
  post-commit doc; row + snapshot written in one transaction.
- `add_resource_opts`: snapshot derived from the resource's doc
  (`build_state_doc`) and written with the row in one transaction;
  `loroUpdate` stripped from the row.
- `ws_apply::persist_update` and `sync::engine::import_sync_push`: merge into
  the stored doc under the subject lock, then funnel through
  `add_resource_opts` — row and snapshot both reflect the merged doc.
- All other `LoroSnapshots` touch points are reads.

Queries now read rows; when nested bodies are requested the raw snapshot is
attached undecoded (see Target architecture §1). If a row is missing
(defensive), the old full path is the fallback.

### Finding 4 — permission check re-fetches the drive per member (mitigated; zones is the real fix)

`check_rights`'s drive fast-path (`lib/src/hierarchy.rs`) did a full decode
of the drive resource per checked member, with a recursive parent walk on
denial. Mitigated this pass by the per-query `RightsCache`: each distinct
subject in the ancestry is resolved once per query, and per-member work is a
hashmap hit + explicit-ACL scan on the row.

**Follow-up 2026-08-10 — the mitigation is incomplete on the *parent* leg.**
The memo keys on a `&Resource`, so `check_rights_impl` must call
`resource.get_parent(store)` — a full `get_resource` decode — *before* it can
find the cached verdict for that parent. The drive fast path avoids this with
an explicit by-subject `cached_deny` probe; the parent walk has no equivalent.
On the real store this is still ~6.7ms/member (parent = 21.7KB form snapshot),
i.e. 0.7s for a 105-member auth-denied query. Details and repro in
[`slow-collection-queries.md`](./slow-collection-queries.md). [`zones.md`](./zones.md) remains
the structural fix (walk-free, index-lookup auth), and its open question —
whether the zone index also makes member-row *reads* skippable for
subjects-only queries — still stands.

### Finding 5 — `QueryMembers` keys embedded the full serialized filter (fixed this pass)

Every member entry carried the whole encoded `QueryFilter` (drive URL +
msgpack, easily 100–200+ bytes) as its key prefix, and `apply_transaction`
re-parsed it per write to emit `QueryMembershipChanged`. Keys now start with
a 16-byte blake3-derived `query_id`; `Tree::WatchedQueries` still stores the
full filter (keyed by its canonical encoding) as the id ↔ filter mapping, and
the live `QUERY_UPDATE` fan-out (`server/src/commit_monitor.rs`) subscribes
by id.

### Finding 6 — every watched filter in a drive was evaluated per atom (fixed this pass)

`check_if_atom_matches_watched_query_filters` iterated all of a drive's
filters for every indexable atom of every commit. The registry now routes by
`(drive, property)`: a filter is registered under each constraint property and
its `sort_by`; only value-only filters stay in a per-drive catch-all bucket.

## Empirical numbers (pre-rework reference)

Isolated measurements against a live server (fixed overhead vs. per-member
cost), before this pass's rework:

| Query shape | Result | Time |
| --- | --- | --- |
| 0 matches (fixed per-request overhead) | 0 members | ~1.7ms warm |
| 1000 matches, single page (`page_size=1000`) | 1000 members | ~101–107ms |
| 1000 matches, `page_size=30` (34 round trips) | 1000 members | ~125ms |
| 1000 matches, `page_size=100` (10 round trips) | 1000 members | ~93ms |

Paired lifecycle benchmark (finding 2's fix isolated): create 3.48ms/op,
edit 2.96ms/op, history 1.24ms/op, query median 131.2ms. NextGraph
comparison: create 14.53ms/op, edit 2.10ms/op, history 0.28ms/op, query
~6.4ms.

### Post-rework results (2026-07-24, fully paired: `f235561e` vs `3578d080`, same machine/session, Rust + HTTP level)

**Queries — verified, the headline win:**

| Level | Before | After | Δ |
| --- | --- | --- | --- |
| Rust, 1000 members, Sudo | 51.8ms | **5.9ms** | **−88.5%** |
| Rust, 1000 members, real agent (per-member rights) | 52.8ms | **7.3ms** | **−86.2%** |
| HTTP, single round trip (`page_size=1000`) | ~101–107ms | **~29–32ms** | **~−70%** |
| HTTP, default client `page_size=30` (34 round trips) | 124.6ms | 60.4ms | −51.5% |

At the single-request level atomic-server went from ~20–25× slower than
NextGraph's ~6.4ms comparison query to **~5×**. With the client default
`page_size=30`, the remaining gap is now dominated by pagination round trips,
not server work — a client calling `.setPageSize(1000)` already gets close to
the single-request number with no further server changes.

**Write path — neutral on a fresh store; earlier claimed gains did NOT
reproduce.** The same paired run measured create +10.1% / edit +6.2% /
history +3.3% at the Rust level and +3.1% / +1.5% (≈ noise) at the HTTP
level. An earlier draft of this section claimed create −12% / edit −14%
based on a Criterion baseline recorded while other work was running on the
machine — the same stale-baseline class of error the methodology note below
warns about. Treat write-path impact on a fresh store as flat-to-slightly-
negative, within noise at the HTTP level.

**Where the filter-routing win actually lives:** commits on a store with
*accumulated* watched filters (the real-world case routing was built for —
leaked filters have historically reached 13k+ and slowed rapid saves). A
paired scaling measurement (`lib/tests/watched_filter_scaling.rs`, 200
creates per round, 0 → 2k → 10k bystander filters on the drive, debug
build):

| Watched filters | Before (`f235561e`), per create | After (`3578d080`), per create |
| --- | --- | --- |
| 0 | 14.5ms | 15.1ms |
| 2,000 | 22.3ms (+54%) | 16.8ms |
| 10,000 | 52.6ms (+263%) | 16.3ms |

Before: per-commit cost grows linearly with unrelated watched filters
(~3.8µs per filter per create). After: flat — 3.2× faster at 10k accumulated
filters. So the routing win is real but conditional on filter accumulation;
it simply doesn't exist on a fresh store, which is why clean lifecycle
benchmarks show no write-path gain.

The remaining ~6ms is dominated by row decode + response assembly for 1000
nested bodies, not CRDT work — this is now in the same order of magnitude as
NextGraph's ~6.4ms comparison query. The non-sudo overhead (rights memo) is
~1.2ms for 1000 members (~1.2µs/member) vs. the former full drive-decode per
member.

### Behavior changes shipped with the rework

1. **Members lacking the sort property are now included in sorted
   collections**, ordered first (the no-value key sorts before every typed
   value). The old key layout dropped them by accident (their empty-value
   separator byte sorted past the default range end) even though `NO_VALUE`
   and the `sortOrder → createdAt` fallback were built to keep them.
   `totalMembers` can therefore grow for collections whose members don't all
   carry the sort property.
2. **Subjects-only queries (`include_nested == false`) no longer return
   resource bodies** in `QueryResult::resources`. The only consumer that read
   them (`collect_members`) already ignored them unless `include_nested` was
   set; per-member authorization is still enforced.

## Design details (as built)

### Shallow query reads

- `Db::get_resource_query_fast(subject, for_agent, attach_snapshot, cache)`:
  row read (`get_resource_shallow`) → memoized `check_read` → optional raw
  `loroUpdate` attach → class-extender `incomplete` marking (same semantics
  as `get_resource_extended(skip_dynamic=true)`). Falls back to
  `get_resource_extended` when no row exists (endpoints, network subjects,
  defensive invariant break).
- Subjects-only queries (`include_nested == false`) never build bodies at
  all — row + rights memo only. Note the old
  `should_include_resource` conflated "needs auth" with "needs bodies";
  these are now separate.

### Rights memo

`hierarchy::RightsCache` — per-query, per `(agent, right)` map of subject
pure-id → allow/deny. Consulted and populated at every recursion boundary of
`check_rights` (self, drive fast-path, parent ascent), so ancestry cost is
paid once per distinct ancestor per query. Public `check_read`/`check_write`
signatures unchanged (they thread `None`).

### QueryMembers key format (`members_index_v6`)

```
[query_id: 16B blake3(filter encoding)]
[typed sort key: tag byte + memcomparable payload, 0x00-escaped]
[0x00 0x00 terminator]
[subject bytes]
```

- Tags: `0x05` no-value < `0x10` bool < `0x20` number (i64/f64/timestamp via
  order-preserving f64 bit-flip) < `0x30` string (case-folded, truncated to
  120 chars, `0x00` → `0x00 0xFF` escape). Mixed-type columns order by tag,
  deterministically. ISO dates are strings and order correctly; numeric
  strings are *not* coerced.
- Prefix correctness: `"a"` sorts before `"ab"` (the old `0xff`-separator
  layout got this wrong, and msgpack bytes containing `0xff` could corrupt
  key parsing — both eliminated).
- Range bounds: start = `id || key(start)`, end = `id || key(end) || 0xFF`
  (inclusive), whole-filter scan = `id` .. `id || 0xFF`.
- Old `members_index_v5` entries are stranded caches; they rebuild on next
  query (same policy as previous bumps).

### Planner

`query_complex`'s index build picks its candidate iterator by estimating each
`(property, value)` constraint's cardinality with a scan-capped prefix count
over `PropValSub` (cap 512), starting from the smallest; the remaining
constraints verify against rows. Single-constraint queries behave as before.

## Remaining work / open questions

- **Counts / pagination**: exact counts still walk the full match range.
  Move the wire contract to cursors + `hasMore` (client default page_size 30,
  `browser/lib/src/collectionBuilder.ts:9`), keep exact counts only under a
  size threshold or on request.
- **Typed keys for `PropValSub`/`ValPropSub` sort segments** once something
  order-sensitive reads them (they're membership indexes today).
- **Batched reads**: one KV read transaction per query (needs `KvStore`
  trait change across redb/sled/btreemap; `redb_store.rs` opens a txn per
  `get`).
- **Watched-filter lifecycle**: every distinct AND-filter query shape creates
  a persistent watched index (`query_complex`). Startup clears them
  (`clear_watched_queries`), but a long-running server accumulates all
  shapes queried since boot. Consider LRU eviction / only materializing on
  second use.
- **Zones** ([`zones.md`](./zones.md)): replaces the rights walk entirely;
  revisit whether it obsoletes the RightsCache and lets subjects-only
  queries skip row reads.
- Per-member cost split post-rework (row decode vs. rights memo hit vs.
  extender scan) hasn't been re-profiled with tracing spans.

## Code references

- `lib/src/db.rs` — `query_basic`, `query_complex`, `get_resource_query_fast`,
  `get_resource_shallow`, `build_index_for_atom`.
- `lib/src/db/query_index.rs` — key encoding, `query_id`, typed sort keys,
  `query_sorted_indexed`, property-routed matching.
- `lib/src/db/trees.rs` — tree version constants.
- `lib/src/hierarchy.rs` — `RightsCache`, `check_rights`.
- `server/src/commit_monitor.rs` — id-keyed query subscriptions.
- `lib/benches/lifecycle_bench.rs` — Criterion benchmarks.
- `browser/lib/src/collectionBuilder.ts:9` — client default `page_size: '30'`.
