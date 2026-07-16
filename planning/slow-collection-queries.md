# Slow collection queries (`/query`)

**Status:** diagnosed, not yet fixed.
**Symptom:** server-side collection queries became "very slow" (multi-second) after
generating ~100 form invite codes with the form builder. Diagnosed 2026-07-16.

## TL;DR

A `/query` request costs roughly
`members × ancestor-chain-depth × Loro-snapshot-parse`. Nothing is cached:
every member gets a full recursive rights walk, every step of that walk
re-fetches the ancestor from the DB, and every `Db::get_resource` re-parses the
resource's full Loro snapshot. The 100 invite codes didn't introduce a
regression — they created the first collection large enough (105 members,
3 parents deep) to push this into seconds.

## Measurements (debug build, user's real store: 30k resources, 1.6GB redb)

Anonymous curl against the running server:

| query | time |
| --- | --- |
| children of server drive (`http://localhost:9883`) | 14ms |
| children of user drive (14 members, sorted) | ~220ms |
| invite codes (`parent=form` + `isA=FormInviteCode`, 105 members) | **3.2–7.4s** |
| same with `page_size=1` | **3.28s** (page size makes no difference!) |
| same without the `isA` filter (plain `parent=form`) | 3.4s |

Fresh dev drive with the identical form + 100 codes: only ~90ms — store scale +
hierarchy depth is what makes it explode, not the query shape.

**Authenticated path** (agent with access, measured with the dev agent owning
an identical 100-code form on the same big store): 368ms cold / ~91ms warm per
`/query`. So a single authenticated query is sub-second; the multi-second
authenticated UX comes from the *aggregate*: the invite panel fetches every
page (`mapAll`) plus one `/did` GET per row (100 requests, each doing its own
`get_resource_extended` + rights walk server-side), and each member fetch
still pays the Loro parse (cause 2). The 3–7s single-request worst case is the
**public/unauthorized agent** (form share page, form definition endpoint),
where cause 3 kicks in.

Chrome trace (`atomic-server --trace chrome`) of ONE 3.5s `page_size=1` request:

- 1,776 `get_resource` calls (~2ms each — that IS the request time)
- 1,760 `check_rights` calls, by subject: **drive 660×, parent folder 660×,
  form 220×** (105 members, ~113 distinct subjects total)
- `export_with_encoded_block` (loro) ran inside every single `get_resource`

Snapshot sizes for the repeatedly-parsed ancestors: form 21.7KB, folder 5.8KB,
drive 2.9KB. Worst snapshots in the store are ~500KB (documents) — any
collection touching those pays 10–30ms per fetch.

## Root causes (three compounding)

1. **No memoization in the rights walk** — `lib/src/hierarchy.rs:98`
   (`check_rights`). Per member it does the drive-first fast path (fetch drive,
   check grant) and on deny the recursive parent walk (member → form → folder →
   drive), re-fetching each ancestor via `get_resource` every time. A
   105-member page resolves the same 3 ancestors ~1,500 times.

   This applies to the *success* path too, not just denials: the drive-first
   check fetches + parses the stamped drive resource fresh for **every
   member**. Note also that the codes' `drive` stamp points at the form's
   parent container (`did:ad:6MvtQw…`), not the top-level drive
   (`did:ad:yNVa…`) — so an agent whose grant lives on the top drive pays a
   2–3 fetch mini-walk per member even when access is granted. Only the
   *creating* agent short-circuits fully: each invite code carries an explicit
   `write: [creator]` array, which `check_rights` matches before any ancestor
   fetch.

2. **`Db::get_resource` parses the full Loro snapshot on every read** —
   `lib/src/db.rs` (`get_resource`, the `Tree::LoroSnapshots` block:
   `AtomicLoroDoc::from_snapshot` + `apply_state_doc`). Propvals are already
   the materialized read cache; the CRDT import is only needed for
   editing/history, but every read — including pure rights-check reads — pays
   it (~2ms each in debug for a 20KB snapshot).

3. **Auth-failed members don't fill the page, so the loop fetches everything**
   — `query_sorted_indexed` (`lib/src/db/query_index.rs`, the
   `in_selection` loop) and `query_basic` (`lib/src/db.rs`). When
   `get_resource_extended` fails auth, `subjects` doesn't grow, so
   `in_selection` stays true and the *next* member is fetched + walked. For an
   unauthorized agent (e.g. the public form share page) even `page_size=1`
   degrades into fetch+walk of ALL members.

Debug build amplifies everything ~5–10×, but the shape is the same in release.

## Fix plan (impact order)

- [ ] **Memoize rights per request.** Cache `(subject, agent, right) →
      verdict` — or at minimum the fetched ancestor `Resource`s — across the
      member loop of one query. Natural place: a small cache created in
      `query_sorted_indexed` / `query_basic` (or carried in `Query` /
      `ForAgent` context) and threaded into `check_rights`. Removes ~85% of the
      `get_resource` calls in the traced request.
- [ ] **Skip Loro snapshot parsing on read-only fetches.** Make
      `Db::get_resource` return propvals-only, loading the Loro doc lazily
      (e.g. `resource.ensure_loro(store)`) at the places that actually need it:
      commit application / `save()` (must build on existing state — see
      CLAUDE.md "always build on existing state"), history, sync. Audit
      callers before changing: anything that edits-and-saves a fetched resource
      currently relies on `loro` being pre-populated.
- [ ] **Cap the auth-failed fetch cascade** in both query loops: once the page
      is over (or after N consecutive auth failures), stop calling
      `get_resource_extended` and only count remaining entries.
- [ ] Re-measure with the repro below; invite-codes query should drop from
      ~3.3s to low tens of ms.

## Repro

The user's slow drive/form (real data, needs their agent for the authenticated
path; anonymous curl reproduces the worst case):

```sh
DRIVE="did:ad:yNVapH3h0-WbiLvD3Kr_v3ambQbadfmYdCoar1WQU8NhNQfaADLznPV9_hjcAY5ECpj3Z1HzPd3qcuDokEiZAA"
FORM="did:ad:VteHUlZq7ms_Xkz3LJpvN3EEZr968JxZM39MBKomzm4fw65-2E7jXeqc_2rtOEOEBETVF-SLFSMVHw--XGUwBw"
enc() { python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$1"; }
curl -s -o /dev/null -w "%{time_total}s\n" -H "Accept: application/ad+json" \
  "http://localhost:9883/query?property=$(enc https://atomicdata.dev/properties/parent)&value=$(enc $FORM)&drive=$(enc $DRIVE)&page_size=1"
```

Synthetic repro at the lib level (better for a regression test): create a drive
with a 3-deep hierarchy, a form with ~100 `FormInviteCode` children, then query
`parent=form` as a *non-authorized* agent and count `get_resource` calls /
assert time. A fresh store won't show wall-clock seconds (small snapshots), so
prefer asserting call counts (e.g. via a counter in the store) over timing.

Profiling: `atomic-server --trace chrome` writes `./trace-<ts>.json`; aggregate
`B`/`E` span pairs per name. The `check_rights` spans carry `subject` in args —
that's how the 660×-drive number above was obtained.

## Side observations (not the cause, worth checking separately)

- `lib/src/db/trees.rs` names trees `watched_queries_v5` / `members_index_v5`,
  but `lib/src/db/redb_store.rs` hardcodes table names `watched_queries_v3` /
  `members_index_v3`. Logical-only mismatch today, but migrations key on the
  string names and could misfire.
- The watched-queries table is emptied **on every server startup, by design**
  (`Db::clear_watched_queries`, called from server startup — see the comment
  in `lib/src/db.rs`: prevents e2e suites leaking 13k+ dead filters). Side
  effect: after every restart, the first access of each sorted/multi-filter
  collection pays a full `Building query index` rebuild in `query_complex`
  (`lib/src/db.rs`), which for multi-filter queries fetches every candidate
  resource. Bounded, but adds to the "collections feel slow" impression during
  dev where the server restarts often.
- Generating codes is itself slow: `FormAccessSection.tsx` does 100
  *sequential* `newResource().save()` round-trips (~9.3s). Could be batched or
  parallelized.
- The invite-code settings panel renders ALL rows (`mapAll`), each row's
  `useMemberFromCollection` fetching its resource — 100 extra `/did` GETs, each
  with its own server-side rights walk. Request-level fixes above also help
  here, but the panel could paginate.
