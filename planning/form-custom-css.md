# Custom CSS for published forms

Status: done.
Related: `planning/atomic-forms.md`, `browser/form-renderer/src/style.css`,
`server/src/forms.rs`, `browser/data-browser/src/chunks/FormBuilder/SettingsTab.tsx`.

## Goal

Let a form owner paste arbitrary CSS in the builder's Appearance settings and
have it apply to the published form (`/form/:id`) and to the builder's Preview
dialog, **without** having to out-specify the renderer's own stylesheet.

## The specificity problem, and why layers solve it

`@tomic/form-renderer`'s `style.css` is a flat, unlayered stylesheet of
`.atomic-form-*` rules, some of them compound (`.atomic-form-card .atomic-form-input`
and friends). Today a user writing `.atomic-form-input { border: 2px solid red }`
loses to any two-class rule of ours, and the only way out is `!important`
everywhere — which then makes *our* future changes unfixable from user CSS.

Cascade layers fix this by ordering, not specificity: **every rule in a later
layer beats every rule in an earlier layer, regardless of specificity.** So a
one-class user rule beats our three-class rule, and the user never thinks about
specificity again. It also protects us: we can freely raise specificity inside
our own stylesheet without breaking anyone's custom CSS.

## Layer plan

Declared once at the top of `form-renderer/src/style.css`, with everything we
ship inside the first layer:

```css
@layer atomic-form-base, atomic-form-custom;
@import 'react-phone-number-input/style.css' layer(atomic-form-base);
@layer atomic-form-base {
  /* the entire previous contents of style.css, unchanged and un-indented */
}
```

`atomic-form-custom` is declared but left empty — it exists so the injected user
CSS lands after our base no matter when its `<style>` element is parsed.

`layer()` on the phone-input `@import` is load-bearing: left unlayered, that
stylesheet would beat both our base rules and the owner's custom CSS.

Wrapping the file re-indented every rule inside the block — oxfmt does this and
`pnpm lint` enforces it, so it is not optional. The result is one large
whitespace-only hunk in this change's diff of `style.css`; there is nothing to
review in it.

**Do not split this into `style.css` + an `@import`ed `base.css`.** That was the
first attempt and it fails: a relative `@import` does not resolve when a
consumer's Vite serves the package from outside its own project root
(`/@fs/…`), which is exactly how `data-browser` loads it — postcss-import ends
up calling `readFile('./base.css')` against the process cwd and the whole
stylesheet 500s. Bare specifiers (`react-phone-number-input/style.css`) resolve
fine; relative ones do not. One file avoids the question.

## Scoping: `@scope (.atomic-form-shell)`

The preview lives in a Dialog **inside the data-browser app**, so unscoped user
CSS (`body { background: black }`) would repaint the builder. Wrapping the user
CSS in `@scope` confines it to the form and keeps the
preview-renders-pixel-identically-to-the-runtime invariant intact — the same
wrapper is used in both places:

```css
@layer atomic-form-custom {
  @scope (.atomic-form-shell) {
    /* user CSS verbatim */
  }
}
```

Inside the scope, `:scope` is the form root — that is where users override the
theme variables (`:scope { --atomic-form-accent: #f0f }`), replacing what they
would otherwise write on `:root`. Bare selectors (`input`, `.atomic-form-card`)
match descendants of the shell, which is what people expect anyway.

Caveats to accept or revisit:

- `@scope` needs Chrome 118 / Safari 17.4 / Firefox 128. Older respondent
  browsers get the base styling only — a graceful degradation, but a silent one.
- `:root`, `body` and `html` rules do nothing. Documented in the editor's help
  text; the shell already paints the page background via `--atomic-form-bg`.
- If the support floor ever bites, the fallback is to rewrite selectors
  server-side with lightningcss's visitor API (prefix each selector with
  `.atomic-form-shell`), which has no support question at all.

## Storage: a dedicated Property, not a `form-styling` key

Add `https://atomicdata.dev/properties/form-custom-css` (datatype `string`) to
`lib/defaults/forms.json`, `urls.rs` and the `Form` class's recommends, rather
than another key inside the `form-styling` JSON blob. Reasons:

- The builder commits styling on every change (debounced). A JSON blob rewrite
  per keystroke round-trips the whole object through Loro; a separate string
  property keeps CSS edits off the styling blob.
- `form-styling` is a small settings bag with a documented key list; a
  multi-kilobyte stylesheet does not belong in it.

It still travels to the runtime **inside** `FormStyling` as `customCss`, next to
`textColor` and friends — that struct is the wire format, and both mirrors
(`server/src/forms.rs` `FormStyling`, `form-renderer/src/types.ts` `FormStyling`)
already have to be kept in lockstep.

## Server: sanitize + minify with lightningcss

`build_form_styling()` (`server/src/forms.rs`) runs the stored CSS through the
`lightningcss` crate (1.0.0-alpha.x, the same engine Vite uses) before putting it
in the definition:

1. **Parse.** A parse error means the CSS is dropped from the definition rather
   than shipped broken. (The builder shows errors up front, see below — this is
   the backstop.)
2. **Strip `@import` and `@charset`.** `@import` would let a published form pull
   a stylesheet from a third-party host on every visitor's browser; the form
   owner can inline what they need. `@font-face` with a remote `src` is the same
   class of thing — decide whether to allow it (leaning yes, it is the main
   reason people want custom CSS) and say so explicitly in the docs.
3. **Minify**, with `targets` set from a browserslist-ish floor so modern
   syntax (nesting, `color-mix`, custom media) gets downleveled for older
   respondent browsers. This is the part that makes user CSS *more* portable
   than hand-written CSS would be.

Cost is sub-millisecond for a few KB and the form routes are `no-store`, so
doing it per definition build is fine — no cache needed.

`css-sanitizer` (crates.io, policy-driven sanitization on top of lightningcss)
may cover steps 1–2 off the shelf; evaluate before hand-rolling the visitor.

Hard cap the stored CSS (~50 KB) in the builder UI and re-check server-side.

## Injecting it

`FormShell` grows an optional `<style>` child rendered from
`definition.styling.customCss`, wrapped in the `@layer`/`@scope` shell above.
No nonce needed: `server/src/handlers/form.rs:312` already sends
`style-src 'self' 'unsafe-inline'` for form pages. Because
`frame-ancestors *` means these pages are embeddable, user CSS is confined to
the iframe in the embed case for free.

## Builder UI

New "Custom CSS" section in `SettingsTab.tsx` (a `SettingsSection`, collapsed by
default — it is an advanced escape hatch, not a first-class setting).

The data-browser already depends on `@uiw/react-codemirror` +
`@codemirror/lint`; add `@codemirror/lang-css` and model the editor on
`components/JSONEditor.tsx`. CodeMirror's CSS mode gives syntax highlighting and
completion; lint diagnostics can come from the CSS mode's own parser so the
owner sees errors before publishing rather than silently losing their styles.

`.atomic-form-*` becomes public API the moment this ships — decided, accepted.
Rather than hand-maintaining a crib sheet of hooks that would drift from the
stylesheet, the editor links straight to `form-renderer/src/style.css` on
GitHub (`RENDERER_STYLESHEET_URL` in `SettingsTab.tsx`, pinned to `develop`).
The stylesheet is the documentation, and it says so in its own header.

## Open questions

- Allow remote `@font-face` / `url()`? It leaks visitor IPs to third parties.
  Owner's call, but worth a line in the docs and maybe a toggle later.
- Per-page CSS, or form-wide only? Form-wide only, to start.

## Testing

Done:

- `server/src/forms.rs`: six `sanitize_custom_css` unit tests (minify, `@import`
  stripped, `@font-face` kept, empty/unparseable/oversized rejected, brace
  breakouts re-serialized balanced) plus two definition-level tests (sanitized
  CSS reaches `styling.customCss`; the key is absent when unset).
- `form-renderer/src/customCss.test.ts`: the `@layer`/`@scope` wrapper is
  emitted around the CSS verbatim, and omitted entirely when there is none.
- `data-browser/src/chunks/CodeEditor/cssLint.test.ts`: brace balancing
  (including braces in comments and strings) and the byte-size cap.
- Manual, in the running app: typed CSS in the builder reaches Preview's
  injected `<style>`; a one-class custom rule beats the two-class base rule
  `.atomic-form-shell-behind .atomic-form-card`, while an unlayered probe rule
  of equal specificity still wins — i.e. the override comes from the layer, not
  from source order. Nothing leaked to the builder's `body`.

- `browser/e2e/tests/forms-submission.spec.ts` ("a published form carries the
  owner's custom CSS", not `@smoke`): builder → publish → anonymous visitor on
  the real route. It asserts the layering rather than merely that CSS applied —
  a bare `h1` beats `.atomic-form-title`, which nothing but a later layer can
  do. Confirmed by mutation: the identical rule in `atomic-form-base` leaves the
  title at `rgb(26, 26, 26)`; in `atomic-form-custom` it turns
  `rgb(200, 0, 50)`. Only the layer differs.

Note when reading a failure here: `forms-submission.spec.ts` has two known
load-related flakes under parallel workers — the embed test can see
`Form not found` before the publish reaches the server, and the drafts test can
find Submit still disabled while altcha is doing its proof-of-work. Both pass
alone. Neither involves styling.
