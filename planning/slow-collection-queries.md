# Slow collection queries (`/query`)

**Status:** ancestor-fetch memo landed 2026-08-14. A consecutive-denial
cap was tried and **reverted**: each member can carry its own grant, so a
private streak must not stop the scan. Original diagnosis 2026-07-16;
last re-measure of the production store 2026-08-10.

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

~90% faster after the index rework, but a 105-member auth-denied query still
cost 0.7s because each member full-decoded the parent. The ancestor-fetch
memo (not re-measured on the production store) pins that to call counts in
`unauthorized_collection_query_bounds_fetch_counts`. A denial-streak cap
was not taken: it would hide later readable rows.

### Cause 1 — no memoization in the rights walk → **fixed**

`hierarchy::RightsCache` + `check_rights_cached` memoize
`(right, subject) → verdict` for one query; `query_basic` and
`query_sorted_indexed` each build one and thread it through
`resolve_query_member`.

The walk now consults that memo by *subject* **before** fetching an
ancestor (drive or parent). A cached allow returns immediately; a cached
deny on the drive still falls through to the parent walk (intermediate
parents can grant); a cached deny on the parent is final. Ancestors are
loaded with `Storelike::get_resource_shallow` (propvals only — `check_rights`
never needs the CRDT), falling back to `get_resource` only if the row is
missing (external / not yet materialized).

### Cause 2 — `get_resource` parses the full Loro snapshot on every read → **fixed for the query path**

`Db::get_resource_shallow` (row-only, no CRDT decode) is now what queries
read; nested bodies get the raw snapshot bytes attached verbatim as
`loroUpdate` instead of a decode+re-export. `Storelike::get_resource`
(`lib/src/db.rs`) still decodes — deliberately; it's the
CRDT-authoritative path. The rights walk no longer calls it for local
ancestors (cause 1).

### Cause 3 — auth-failed members don't fill the page → **left as-is**

Denied members do not consume `page_size`, so the loop keeps
`resolve_query_member` until it has `limit` *authorized* hits (or the
index is exhausted). That is required: a resource can have its own
`read` grant even when every previous sibling was private
(`unauthorized_query_skips_denials_to_fill_the_page` — 20 private, then
one public, `page_size=1`).

A consecutive-denial cap would make the all-denied invite-code listing
cheaper, but would hide later readable rows after a private streak. The
ancestor-fetch memo (cause 1) is the speedup that stays correct: each
member is still a cheap shallow row read + a cache hit on the parent,
not a Loro decode of the form.

## Open items

- [x] **Memoize the parent *fetch*, not just the verdict.**
- [x] **Cap the auth-failed fetch cascade** — *declined.* Stopping after N
      consecutive denials would skip later members the agent *can* read.
      Keep scanning until the page is full of authorized hits; the parent
      memo makes that cheap.

## Repro

```sh
DRIVE="did:ad:yNVapH3h0-WbiLvD3Kr_v3ambQbadfmYdCoar1WQU8NhNQfaADLznPV9_hjcAY5ECpj3Z1HzPd3qcuDokEiZAA"
FORM="did:ad:VteHUlZq7ms_Xkz3LJpvN3EEZr968JxZM39MBKomzm4fw65-2E7jXeqc_2rtOEOEBETVF-SLFSMVHw--XGUwBw"
enc() { python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$1"; }
curl -s -o /dev/null -w "%{time_total}s\n" -H "Accept: application/ad+json" \
  "http://localhost:9883/query?property=$(enc https://atomicdata.dev/properties/parent)&value=$(enc $FORM)&drive=$(enc $DRIVE)&page_size=1"
# add &offset=1000 to see the same query with the per-member loop skipped
```

Synthetic repro (now a regression test): drive → folder → form → ~100
children, query `parent=form` as a *non-authorized* agent, assert
`get_resource` / `get_resource_shallow` call counts — not wall clock.
See `unauthorized_collection_query_bounds_fetch_counts` in
`lib/src/db/test.rs`.

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
  (`Db::clear_watched_queries`), so the first sorted /
  multi-filter query after a restart still pays an index rebuild.
- `createInviteCodes` (`browser/data-browser/src/chunks/FormBuilder/FormAccessSection.tsx:54`)
  still saves codes in a sequential `for` loop (~9.3s for 100).
- The invite-code panel still renders all rows via `mapAll`
  (`FormAccessSection.tsx:275`), each row's `useMemberFromCollection` fetching
  its own resource. Those per-row GETs go through `get_resource_extended` →
  `check_rights` with **no** memo (the memo is per-query, not per-request).
  Cause 1 still helps each GET (ancestors are shallow-fetched), but there is
  still one rights walk per row rather than one per listing.

