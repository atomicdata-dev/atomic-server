# Slow collection queries (`/query`)

**Status:** two of three causes fixed by the index/query rework
(`3578d080`, see [`index-performance.md`](./index-performance.md)); **two
items still open**, re-measured 2026-08-10 against the same real store.
Original diagnosis 2026-07-16.

## Where it stands

Re-ran the repro below against the user's real store (30k resources, debug
build, anonymous agent) on a binary built after the rebase:

| query | 2026-07-16 | 2026-08-10 |
| --- | --- | --- |
| 0 matches (fixed per-request overhead) | — | **12ms** |
| children of server drive | 14ms | **12ms** |
| children of user drive (14 members) | ~220ms (sorted) | **33ms** (unsorted — not a like-for-like) |
| invite codes (`parent=form`, ~105 members), `page_size=1` | 3.2–7.4s | **0.71–0.76s** |
| same, `page_size=100` | 3.4s | **0.69s** |
| same, `page_size=1&offset=1000` (skips all per-member work) | — | **11ms** |

~90% faster, but a 105-member auth-denied query still costs 0.7s, and page
size still makes no difference.

### Cause 1 — no memoization in the rights walk → **fixed (partially)**

`hierarchy::RightsCache` + `check_rights_cached` memoize
`(right, subject) → verdict` for one query; `query_basic` and
`query_sorted_indexed` each build one and thread it through
`resolve_query_member`. The drive fast path also got an explicit
`cached_deny` short-circuit that skips the drive fetch entirely.

**But the parent walk did not get the same treatment** — see open item 1.

### Cause 2 — `get_resource` parses the full Loro snapshot on every read → **fixed for the query path**

`Db::get_resource_shallow` (row-only, no CRDT decode) is now what queries
read; nested bodies get the raw snapshot bytes attached verbatim as
`loroUpdate` instead of a decode+re-export. `Storelike::get_resource`
(`lib/src/db.rs:3034`) still decodes — deliberately; it's the
CRDT-authoritative path. That's fine except where the rights walk calls it
(open item 1).

### Cause 3 — auth-failed members don't fill the page → **still open**

Unchanged in `query_sorted_indexed` (`lib/src/db/query_index.rs:273`) and
`query_basic` (`lib/src/db.rs:2110`): `in_selection = subjects.len() < limit
&& i >= q.offset`. A denied member never grows `subjects`, so every
subsequent entry is still fetched and rights-walked. Measured cost of exactly
this: the same query at `offset=1000` (where `i >= q.offset` is false, so the
loop only counts) is **11ms vs 700ms** — a 64× gap that is entirely
per-member work the client never sees.

## Open items

- [ ] **Memoize the parent *fetch*, not just the verdict.**
      `check_rights_impl` (`lib/src/hierarchy.rs:339`) calls
      `resource.get_parent(store)`, which does a full
      `store.get_resource(parent)` — Loro snapshot decode and all — *before*
      `check_rights_cached` can consult the memo, because the memo takes a
      `&Resource`. So each member pays one full decode of the form's 21.7KB
      snapshot even though the verdict for that parent is already cached.
      Confirmed by the cost scaling with parent snapshot size: ~6.7ms/member
      when the parent is the 21.7KB form, ~2.3ms/member when it's the 2.9KB
      drive.
      Fix: consult the memo by *subject* before fetching (the drive fast path
      at `hierarchy.rs:321` already does exactly this with `cached_deny` —
      generalize it), and/or fetch ancestors with `get_resource_shallow`, since
      `check_rights` only reads propvals.
- [ ] **Cap the auth-failed fetch cascade** (original cause 3, unchanged):
      once the page is full — or after N consecutive denials — stop calling
      `resolve_query_member` and only count the remaining entries.

Either fix alone should take the repro well under 100ms; both should land it
near the 12ms fixed overhead.

## Repro

```sh
DRIVE="did:ad:yNVapH3h0-WbiLvD3Kr_v3ambQbadfmYdCoar1WQU8NhNQfaADLznPV9_hjcAY5ECpj3Z1HzPd3qcuDokEiZAA"
FORM="did:ad:VteHUlZq7ms_Xkz3LJpvN3EEZr968JxZM39MBKomzm4fw65-2E7jXeqc_2rtOEOEBETVF-SLFSMVHw--XGUwBw"
enc() { python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$1"; }
curl -s -o /dev/null -w "%{time_total}s\n" -H "Accept: application/ad+json" \
  "http://localhost:9883/query?property=$(enc https://atomicdata.dev/properties/parent)&value=$(enc $FORM)&drive=$(enc $DRIVE)&page_size=1"
# add &offset=1000 to see the same query with the per-member loop skipped
```

Synthetic repro for a regression test: drive → folder → form → ~100
`FormInviteCode` children, query `parent=form` as a *non-authorized* agent,
assert `get_resource` call counts (not wall clock — a fresh store's snapshots
are too small to show it).

Profiling: `atomic-server --trace chrome` writes `./trace-<ts>.json`;
`check_rights` spans carry `subject` in args.

## Side observations

- **Tree-name mismatch (still there, and wider).** `lib/src/db/trees.rs:44,46`
  name the trees `members_index_v6` / `watched_queries_v5`, while
  `lib/src/db/redb_store.rs:26,28` hardcode `members_index_v3` /
  `watched_queries_v3` — with a comment claiming they must stay in sync.
  `lib/src/db/migrations.rs` only migrates sled and only up to v3. Low impact
  today (`WatchedQueries` is cleared on startup, and pre-rework `QueryMembers`
  keys can't collide with the new 16-byte `query_id` prefix, so stale entries
  are unreachable garbage rather than bad reads) — but they never get dropped,
  and the next key-format change has no working version gate on redb.
- Watched queries are still emptied on every server startup by design
  (`Db::clear_watched_queries`, `lib/src/db.rs:1729`), so the first sorted /
  multi-filter query after a restart still pays an index rebuild.
- `createInviteCodes` (`browser/data-browser/src/chunks/FormBuilder/FormAccessSection.tsx:54`)
  still saves codes in a sequential `for` loop (~9.3s for 100).
- The invite-code panel still renders all rows via `mapAll`
  (`FormAccessSection.tsx:275`), each row's `useMemberFromCollection` fetching
  its own resource. Those per-row GETs go through `get_resource_extended` →
  `check_rights` with **no** memo (the memo is per-query, not per-request), so
  open item 1 hits them too.
