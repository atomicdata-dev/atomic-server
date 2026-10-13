# Atomic brand assets

Single source of truth for every Atomic icon and favicon, across all apps and
repositories.

> **Licensing:** the files in this directory are **not** MIT licensed, unlike the
> rest of this repository. See [`LICENSE`](./LICENSE) and
> [`../TRADEMARKS.md`](../TRADEMARKS.md). Reserving the marks is what lets the
> code stay permissively licensed.

## The marks

| File | Used for |
| --- | --- |
| `src/place-mark.svg` | Atomic Place — browser app, portal and marketing site |
| `src/place-mark-mono.svg` | single-ink Atomic Place favicon contexts |
| `src/atomic-mark.svg` | AtomicServer — server and existing native/docs/package icons |
| `src/atomic-mark-mono.svg` | single-ink contexts (Safari pinned tab). Ring and orb are separated by a real gap instead of the colour mark's white keyline, which carries no information once flattened |
| `src/canvas-mark.svg` | Atomic Canvas — the open sweep. Same orb, same gradient, same family |

Colours: the orb ramps `#01ECFF` (right) → `#2210FF` (left). The Atomic mark's ring is black; the Place mark's trail is white on a dark `#111111` tile.
That gradient is the one brand constant — every mark shares it.

## Regenerating

```sh
node brand/generate.mjs
git diff                  # empty = nothing drifted
```

Requires `rsvg-convert` and ImageMagick 7 (`brew install librsvg imagemagick`).
The `.icns` additionally needs macOS `iconutil`; on other platforms that one
target is skipped with a warning.

Derived files **are committed**, so app builds and offline checkouts need no
image tooling — only regenerating does.

### Why there is no `--check` mode, and no CI job

Rendering is deterministic: running the generator twice produces byte-identical
output. So `git diff` after a run already answers "has anything drifted?"
exactly, reusing the byte-differ we already have.

A CI version cannot work that way. Runners have different librsvg and
ImageMagick versions, which do not encode identical bytes, so it would have to
compare images *perceptually* — which in practice meant a similarity threshold,
an ImageMagick 6-vs-7 shim, a byte-compare fallback for `.icns` (no decode
delegate), a frame-index workaround for `.ico` (comparing a container against
itself reports differences), and a duplicated path filter in the workflow.
That was ~126 lines and five separate workarounds guarding against a
cosmetically stale icon. Not worth it. Deleted deliberately — please don't
re-add it without a better reason than symmetry.

## Editing rules

1. Change `src/*.svg`, never a generated file. Every icon in every app is
   overwritten from these three.
2. Re-run the generator and commit the result in the same change.
3. Adding a surface means adding an entry to `TARGETS` in `generate.mjs`, not
   copying a PNG by hand.

### One trap worth knowing

`atomic-mark.svg` re-bases the original artwork onto a clean `0 0 100 100`
viewBox with a `translate(-108,-28)` on the group. The gradient uses
`gradientUnits="userSpaceOnUse"`, which resolves in the *translated* space —
so its coordinates deliberately stay in the old range (`x1="167"`). Re-basing
them to match the viewBox silently flattens the orb to solid cyan, with no
error. If the orb ever loses its gradient, look here first.

## Coverage

Generated into, across three repositories:

- `atomic-server` — data-browser favicon set, Tauri desktop + iOS icons, mdBook
  docs, svelte package, sveltekit starter template, root `logo-square.svg`
- `atomic-server/flutter` — Atomic Canvas web, iOS and Android launcher icons
- `atomic-saas/portal` — portal favicon set
- `atomic-saas/site` — marketing site icons (Next.js App Router picks up
  `icon.svg` / `apple-icon.png` by filename convention, so there are no
  `<link>` tags to keep in sync)

The sibling repo is located relative to this one (`../atomic-saas`) and skipped
with a warning when not checked out, so the generator still works from a lone
`atomic-server` clone.

### Why a push model rather than consumers declaring their own source

Web consumers could plausibly import a mark and let their bundler emit
favicons. The native ones cannot: Tauri wants `.icns`/`.ico` at paths fixed by
`tauri.conf.json`, Xcode wants an `AppIcon.appiconset` whose filenames are
pinned by `Contents.json`, and Android wants `ic_launcher.png` in five
`mipmap-*` directories. None of those offer a "fetch it from here" hook — the
files must exist, pre-rendered, at exact paths.

So a consumer-declared manifest would be a *third* place the paths are
written, after the framework config and the file layout itself. `TARGETS` in
`generate.mjs` is one list covering all of them, and it is the only place a
path appears that the framework did not already dictate.

## Wordmarks are hand-maintained

The Atomic Place wordmark is an SVG lockup with a normal `o` in “atomic” and a
gradient full stop before “place”. Its letterforms and dot are currently kept
in sync by hand across these surfaces:

| File | Use |
| --- | --- |
| `logo.svg` and `logo-dark.svg` | Repository README in light and dark themes; Dagger mounts `logo.svg` at `/logo.svg` |
| `browser/data-browser/index.html` | Browser boot splash, using `--text-splash` for the letters |
| `browser/data-browser/src/components/Logo.tsx` | App UI, using the current theme for the letters |
| `atomic-saas/portal/src/PlaceLogo.tsx` | Managed portal header in the sibling repo |

When changing the lockup, update all four from the same geometry. The root
`logo.svg` uses black letters and `logo-dark.svg` uses white letters; the
inline versions use their surface's current text colour. The dot keeps its
cyan-to-blue gradient.
The browser splash and React logo need to remain inline so their letters can
follow the app theme before and after startup.

`browser/logo.svg` and `browser/data-browser/logo.svg` are older Atomic Data
Browser lockups, separate from the Atomic Place wordmark.

## Atomic Place web identity — September 2026

`src/place-mark.svg` and `src/place-mark-mono.svg` supply the centred-orb
icon for the data-browser web app, SaaS portal and marketing site. Native
app and specification icons retain their existing sources for now.

The Place mark is the hero's orbit as a fading trail: 48 stacked arc bands
whose opacity ramps from nothing at 3 o'clock to solid at the top, a dot at
its head and the gradient orb in the middle, in white on a dark rounded tile
with no keyline. The bands come from `orbitTrailMarkup('#fff')` in
`browser/data-browser/src/helpers/orbitTrail.ts`, the same generator the app's
loader uses, and are inlined in `place-mark.svg` between `orbit-trail`
comments; `orbitTrail.test.ts` fails if they drift. To change the trail,
regenerate that block and then run the generator. Because the tile is dark,
the opaque variants (`flat`, `maskable`) fill with `#111111` instead of white
(`TILE_BACKGROUND` in `generate.mjs`). `place-mark-mono.svg` stays a solid
single-ink mark for Safari's pinned tab. Regenerate
only the web surfaces with:

```sh
node brand/generate.mjs --target=browser/data-browser/public/app_data/images --target=portal/public --target=site/src/app
```

The app wordmark in `Logo.tsx` and the boot splash spell `atomic.place` with
a normal o and gradient full stop. Existing developer identifiers and hosting
origins remain unchanged in this visual rollout.
