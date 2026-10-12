# pnpm patches

Every file here is applied by `patchedDependencies` in `../pnpm-workspace.yaml`.
A patch is a liability: it pins the exact version it was made for, silently
stops applying on a bump, and hides a bug the upstream project does not know
about. Each entry below says why the patch exists and what has to happen for
it to go away. When you add one, add it here and open an upstream issue or PR.

## loro-prosemirror@0.4.3.patch

Added in #1488. Changes to the ProseMirror ↔ Loro binding:

- Restore the selection in the same transaction as a remote update instead
  of from a `setTimeout`, which could overwrite a newer local cursor.
- Preserve explicit pending formatting at an empty selection across imports;
  otherwise a sync receipt between toggling bold and typing clears the toggle.
- Apply a single inline `ReplaceStep` straight to the existing `LoroText`
  instead of reconciling the whole tree, so typing stays fast in paragraphs
  with a long formatting history.
- Cache `toDelta()` per reconciliation pass.

Upstream: [loro-dev/loro-prosemirror#85](https://github.com/loro-dev/loro-prosemirror/pull/85)
and [#86](https://github.com/loro-dev/loro-prosemirror/pull/86). Upstream 0.4.4
already contains the "only emit changed style ops" part, so do not bump past
0.4.3 without rebasing the patch. Removal steps: [#1494](https://github.com/ontola/atomic-server/issues/1494).

## @reactflow__core.patch

Added in #1382. Silences the spurious `error002` ("node types object changed")
warning that fires in development when the `nodeTypes` object is referentially
stable. Compare the reference before warning. No upstream PR; `@reactflow/core`
is superseded by `@xyflow/react`, so the patch goes away with that migration.

## playwright-core@1.63.0.patch

Added in #1463. Disables the Chromium `PreventCrossWorldServiceWorkerResourceReuse`
feature, which confuses `null` and `MainWorld()` in service-worker preload
matching on Chromium 153 and breaks E2E runs. Remove once the browser Playwright
bundles includes `chromium/chromium@4df9ee2790a4`.

## wuchale@0.25.6.patch

Fixes message extraction for JSX that sits inside an expression rather than
directly in its parent's children (`{cond && <X/>}`, a ternary, `.map(...)`,
an attribute such as `title={<span>...</span>}`). Wuchale visited those trees
against the enclosing level's pending state. A text-less element there, as in
`{a && <p>{x}</p>}`, applied and reset that state early, so the messages of
every later sibling were silently dropped: they rendered untranslated and
never reached the `.po` files, and `pnpm clean-translations` removed their
entries (for example "Fetch workspace", "Restore version"). Other trees had
their text folded into the enclosing level and were extracted as sentence
fragments ("Searching for", "for"). The patch gives each such tree its own
state and applies it when the tree ends. It applies to the CLI and the vite
plugin alike, since both use `MixedVisitor`.

Upstream: not yet reported; the same code shape is still in wuchale 0.26.7.
Remove when an upstream release isolates expression children in
`adapter-utils/mixed-visitor.js`, then re-run `pnpm clean-translations` and
check that no entries move.

## @wuchale/jsx@0.12.5.patch

The runtime component that renders a message with markup in it (an icon next
to a label, a link inside a sentence) returns the pieces as an array, and the
elements in it carry no key. In development React logs "Each child in a list
should have a unique key" for every such message, with the owner named after
the surrounding component (for example `TitleDecorationAffordances`). The
patch wraps each piece in a `Fragment` keyed by its position, which cannot
change for a given message. Production builds never logged it, but a Vite dev
server does, and the atomic-saas portal e2e runs one and fails on any console
error. `Children.toArray` does not help: React still warns for elements it
keys that way.

Upstream: not yet reported. Remove when the `@wuchale/jsx` runtime keys the
pieces it returns; `src/locales/wuchaleRuntime.test.tsx` fails if it does not.
