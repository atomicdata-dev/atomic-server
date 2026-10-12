# Min / max length on text questions

Let a form author bound how long an answer to a text question may be
(`short-text`, `long-text`).

## Decisions

- **Stored in the `form-field-options` bag** as `minLength` / `maxLength`,
  the same call as `minSelected`/`maxSelected` and `minRows`/`maxRows`: the
  bound is a property of the *question*, not of the String column the answer
  lands in.
- **Distinct keys, not `min`/`max`.** `min`/`max` already mean value bounds
  on `number`/`currency` and steps on `rating`; a length bound reading the
  same key would be one copy-paste away from a wrong error message.
- **Only the two text types.** `email`, `url`, `phone` and `country` share
  `TextOptions` but have their own shape rules; a length bound on top of
  those is not what was asked for, so `TextOptions` takes a flag.
- **Neither bound is a hard cap; both are checked on submit.** A native
  `maxlength` was the first cut, and it is wrong here: it silently eats a
  paste, and the visitor never learns by how much they are over. Instead the
  field carries a live `5/200` counter that goes red past the maximum, along
  with the input's border (`aria-invalid`), and `validatePage` refuses the
  submit. This is where text parts ways with `minSelected`/`maxSelected`,
  whose options simply grey out — trimming a sentence is work, ticking one
  fewer box is not.
- **Only the minimum is spelled out in words.** "At least 3 characters" on
  the left, the counter on the right; the counter's denominator already says
  what the maximum is.
- **The overflow itself is coloured red, where the browser can.** The CSS
  Custom Highlight API plus `createValueRange()` — the opaque-range proposal,
  the only way to name a slice of a form control's *value* — paint the
  characters past the maximum without wrapping them in an element. Both are
  new: Firefox and recent Chrome have them, Chromium 148 (what Playwright
  ships) has the highlight half only. So it is a pure enhancement, feature-
  detected and wrapped in try/catch; the counter, the red border and the
  refused submit are the part every browser gets.
- **A blank answer stays "unanswered", not "under the minimum".** `minLength`
  only applies to a non-empty answer; making a field mandatory is what
  `required` is for.
- **Characters are counted in UTF-16 code units** — what JS `.length` and the
  native `maxlength` attribute count. The server therefore counts
  `encode_utf16()`, not `chars()`, so both sides agree on an emoji.

## Tasks

- [x] `browser/form-renderer/src/types.ts` — the two option keys.
- [x] `validation.ts` — `lengthBounds()` / `minLengthHint()` /
      `isOverLength()` + the check in the `short-text` / `long-text` arm;
      unit tests.
- [x] `FieldInput.tsx` / `style.css` — the counter under the input,
      `aria-invalid` past the maximum and the red border it earns.
- [x] `overflowHighlight.ts` / `style.css` — the `::highlight()` rule and the
      feature-detected registration behind it; unit tests for both the
      supported and the unsupported browser.
- [x] `chunks/FormBuilder` — the min/max pair in `TextOptions`, behind a
      `lengthBounds` prop set for the two text types in `FieldSettingsPanel`.
- [x] `server/src/forms.rs` — the same check in `coerce_value`, unit test.
- [x] `docs/src/schema/forms.md` — the two rows of the question-type table.
