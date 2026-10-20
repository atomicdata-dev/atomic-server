# Move resource

Menu item "Move..." (`actions/resourceActions.tsx`, `MoveResourceDialog.tsx`, `helpers/moveResource.ts`).

## Same drive
- [x] Dialog with `ResourceSelector`, write-rights check on the target, blocks self, descendants and content-addressed properties
- [x] Access-follows-parent note
- [x] Unit test (`helpers/moveResource.test.ts`)
- [ ] Screenshots + e2e (only if the smoke tier needs it)

## Other drive
Done: `copyResourceTree` + `replaceWithRedirect` (`helpers/moveResource.ts`), the dialog's other-drive
warning and "Leave a redirect at the old location" checkbox (off = original to Trash), and
`routes/ShowRoute.tsx` following a stored `Redirect` to its `destination`.

How it works: copy = fresh genesis ids, children via `parent`, references inside the copied set
rewritten, rights not carried over (they follow the new parent). Files are copied by value; blobs
are content-addressed, so the copy points at the same bytes. Rich-text bodies are seeded from the
original's Loro doc. The original keeps parent/drive/genesis/rights and is overwritten to
`isA=Redirect` + `destination`.

- [ ] Descendants of the original stay under the Redirect (hidden, still reachable by id); trash or destroy them
- [ ] Trees with Properties/Tables (content-addressed ids) are refused; copying needs the ids re-derived
- [ ] Links inside rich-text bodies are not rewritten to the new ids
- [ ] Redirect shows up as an untitled row in the old parent's sidebar; give it a title/icon or hide it
- [ ] Screenshots + e2e (only if the smoke tier needs it)
