# ShortLinks — generic shortened resource identifiers

Design note. Replaces the form-specific `publish-id → subject` redb map
(`server/src/forms.rs`, `PUBLISH_SLUG_MAP_KEY` in `Tree::PluginMeta`) with a
generic, store-native mechanism. Came out of the Phase 6 private-links
discussion in [`atomic-forms.md`](./atomic-forms.md).

## Problem

Subjects are `did:ad:{genesis}` — too long/ugly for share URLs. Forms solved
this with a slug stored two ways: a `form-publish-id` property on the Form
(display) plus a server-global redb map (authoritative lookup). Problems:

- **Two sources of truth** to keep in sync; destroying a form leaks a stale
  map entry forever (dead slug → dead subject, never cleaned up).
- **Not reusable**: every future feature needing short identifiers (share
  links, invite links, vanity URLs, published-page routes) would grow its own
  hand-rolled redb map with its own sync/GC/versioning story.
- The obvious alternative — resolve by querying the `form-publish-id`
  property via the global `PropValSub` index — works mechanically
  (`query_basic` path, no watched-query cost) but has no uniqueness or
  ownership guarantee: any user can write `form-publish-id: <victim's slug>`
  onto their own form via a normal commit and hijack the slug. Defending that
  needs new enforcement (multi-hit 404s, server-managed-property guards on
  the generic commit path — exactly what forms decision #1 avoids).

## Design: slug-as-subject

**The subject is the store's one true unique index — make the slug a subject.**

A `ShortLink` class. Instances live at a deterministic subject:

```
internal:/shortlinks/{slug}
```

parented under a single server-owned `internal:/shortlinks` container.

| property           | type     | notes                                  |
| ------------------ | -------- | -------------------------------------- |
| `shortlink-target` | Resource | the subject this slug resolves to      |

Every hard property falls out structurally, with no new enforcement code:

- **Uniqueness** — the store is a subject-keyed map. Minting a slug whose
  subject already exists simply fails; retry with a new random slug. Same
  mechanism gives vanity-slug availability checks for free later.
- **Resolution** — direct `store.get_resource("internal:/shortlinks/" + slug)`.
  O(1), no query index, no watched-query registration. Cheaper than both the
  redb map and a property query.
- **Anti-forgery** — users cannot create children under the server-owned
  `internal:/shortlinks` container; the *existing* hierarchy rights check
  rejects the commit. No form-specific (or shortlink-specific) logic on the
  `/commit` path.
- **Everything else free** — normal resource: commit history as audit trail,
  `destroy()` for deletion, sync, backup. No `PluginMeta` blob versioning.

Denormalized back-references on the target (e.g. `form-publish-id` on the
Form, read by `ShareLinkPanel`) may stay as display conveniences, but they
are **cosmetic**: resolution never reads them, so forging one accomplishes
nothing.

## API (server-side, feature-agnostic)

```rust
mint_short_link(store, target: &Subject) -> AtomicResult<String>
    // random base58 slug (URL-safe, no confusable pairs — keep it),
    // create-or-retry on subject collision, small mutex (or
    // create-then-verify) so concurrent mints of the same slug can't
    // both think they won

resolve_short_link(store, slug: &str) -> AtomicResult<Subject>
    // direct get, returns shortlink-target; 404 on missing/dangling
```

Each feature's handler adds its own one-line check on the **target** — the
form handler verifies `isA` Form + published state, exactly as today — so a
slug minted for one purpose can't be replayed against another feature's
route.

## Lifecycle

- **Unpublish** (forms): keep the ShortLink; the handler already gates on
  `published-at` (410). Republishing keeps the same URL — links in
  already-sent emails survive a publish toggle.
- **Delete target**: the owning feature's delete flow destroys the ShortLink
  too (forms: `DeleteFormDialog` cascade). A missed cleanup fails safe:
  resolve treats a dangling target as 404.
- **Multi-drive**: `internal:/` is root-drive/server territory — matches the
  already-made decision that slugs are server-global (same as `did:ad:`
  subject resolution).

## Scope boundary

ShortLinks solve the server-global "short URL → resource" problem **only**.
Per-feature data with owner-managed lifecycle — e.g. form invite codes —
should be modeled as children of the owning resource instead (codes: children
of the Form, looked up via the `form-code` basic-path `PropValSub` index +
parent check; see the private-links section of `atomic-forms.md`). Do not
route those through ShortLinks.

## Migration / refactor plan

- [ ] `ShortLink` class + `shortlink-target` property in `lib/defaults`
      (or server-side-only class if we don't want it in the public ontology —
      decide; leaning public, it's honest data).
- [ ] `internal:/shortlinks` container created in populate (server-owned, no
      public write).
- [ ] `mint_short_link` / `resolve_short_link` in `server/src/` (or `lib` if
      the flutter/iroh side ever needs it — start server-side).
- [ ] Rewire `server/src/forms.rs::{mint_publish_slug, resolve_form}` onto
      the new API; delete `PUBLISH_SLUG_MAP_KEY` and the map (de)serialization.
- [ ] `resolve_form` keeps accepting raw `did:ad:` subjects as fallback
      (unchanged behavior).
- [ ] Existing dev forms: no data migration (forms are beta, per
      `atomic-forms.md` decision #6 precedent). A form with a
      `form-publish-id` but no ShortLink resource just re-mints on next
      publish/definition fetch — old slug URLs from dev data may break;
      acceptable.
- [ ] Tests: mint collision-retry, resolve happy/dangling/unknown, rights
      check that a non-server agent cannot create under
      `internal:/shortlinks`, forms integration still green
      (`cargo test -p atomic-server --lib`).

## Open questions

- [ ] Slug length/alphabet: keep 10-char base58 from forms, or shorten now
      that collisions are structurally handled (retry loop)? Leaning: keep 10.
- [ ] Vanity slugs (user-chosen, e.g. `my-survey`): mechanism supports it
      trivially (availability = subject existence); needs reserved-word list
      (`app`, `form`, `agents`, …) before exposing. Not scheduled.
- [ ] Should ShortLink record a `purpose`/`isA`-of-target hint for nicer 404
      pages? Probably unnecessary — handlers check the target anyway.
