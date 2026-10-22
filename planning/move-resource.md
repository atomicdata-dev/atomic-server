# Move resource

Menu item "Move..." (`actions/resourceActions.tsx`, `MoveResourceDialog.tsx`, `helpers/moveResource.ts`).

## Same drive
- [x] Dialog with `ResourceSelector`, write-rights check on the target, blocks self, descendants and content-addressed properties
- [x] Access-follows-parent note
- [x] Unit test (`helpers/moveResource.test.ts`)
- [ ] Screenshots + e2e (only if the smoke tier needs it)

## Other drive (blocked: no copy API)
A drive is immutable, so this is copy + replace. Nothing in `@tomic/lib` copies a resource:
`store.newResource` creates a fresh genesis, but there is no helper that clones propvals,
rewrites references among the copied resources, carries blobs (files hold a blob id plus
drive-bound rights) or recreates children. That is a feature of its own, not a small addition.

- [ ] `store.copyResourceTree(subject, targetParent)`: walk children (collection query on `parent`), `newResource` per node, map old to new subjects, rewrite resource-valued props that point inside the copied set, skip server-managed props (`drive`, `parent`, `lastCommit`, rights)
- [ ] Decide files/blobs: re-upload vs. reference
- [ ] Dialog: when another drive is picked, state the id and link change and that old links stop pointing at it; checkbox "Leave a redirect at the old location" (default on)
- [ ] Redirect: replace the original with a `Redirect` (`https://atomicdata.dev/classes/Redirect`, `destination` = new subject) or trash it; needs delete/replace of a genesis resource to be checked
- [ ] Until then `moveBlockedReason` returns "Moving to another drive is not supported yet."
