# More form field types — DONE

Work item split out of Phase 6 of [`atomic-forms.md`](./atomic-forms.md) ("More
field types"). **File upload is deliberately not part of this item** — it needs
an anonymous upload path (`POST /form/:id/upload`) and gets its own work item.

Each type = enum value + options schema + builder settings UI + renderer input +
client validator + server validator/coercion + datatype mapping + summary
routing. Summary/results handling deliberately **reuses the existing
per-datatype paths** (choice counts / number histogram / text sample) — no new
charts.

## Type table (as shipped)

| type | Property datatype | `form-field-options` | submitted value |
| --- | --- | --- | --- |
| `phone` | String | `{placeholder}` | string, E.164 from the renderer's country-select input; loose phone shape still accepted |
| `country` | String | `{placeholder, defaultCountry}` | ISO 3166-1 alpha-2 code |
| `url` | String | `{placeholder}` | string, `https?://…` |
| `currency` | Float | `{currency, min, max, placeholder}` | number |
| `dropdown` | String | `{options[], placeholder}` | string ∈ options |
| `dropdown-multi` | JSON | `{options[]}` | string[] ⊆ options |
| `likert` | Integer | `{scale, minLabel, maxLabel}` | int 1..scale |
| `rating` | Integer | `{max, icon}` | int 1..max |
| `picture-choice` | String | `{options[], optionImages[]}` | string ∈ options |
| `choice-matrix` | JSON | `{rows[], columns[]}` | `{row: column}` |
| `table-input` | JSON | `{columns[{label,type}], minRows, maxRows}` | `[{col: value}]` |
| `address` | JSON | `{}` | `{line1,line2,postalCode,city,state,country}` |

Decisions worth keeping:

- **`optionImages` is a parallel array** indexed against `options` (not a
  label-keyed map) so renaming an option label keeps its image.
- **Picture-choice images ride the publish-gated image route.** `/download` is
  rights-checked, so `GET /form/{id}/image` grew a `?file=<subject>` param,
  gated on the subject actually being referenced by this form
  (`forms::collect_option_image_subjects`) — without that check the route would
  be an open proxy for anything the server agent can read. Subjects are
  rewritten into those URLs by `fill_image_url` in the handler, exactly like
  `styling.imageUrl`, so `build_form_definition` stays id-agnostic. The builder
  preview instead resolves them to the File's own `downloadURL`
  (`buildFormDefinition.ts::resolveOptionImages`), same split as the cover image.
- **Empty-value semantics grew an object case, and arrays got stricter**: an
  array or object whose entries are all themselves empty (an untouched
  `table-input` grid, a blank `address`) now counts as unanswered, in both
  `conditions.ts::isEmptyValue` and Rust `json_is_empty`. `validate_submission`
  now calls `json_is_empty` instead of its own inline copy.
- **Required-ness is per-subfield on composites**: `choice-matrix` needs every
  row answered, `address` needs line1 + city + country. That's why
  `coerce_value` takes a `required` flag.
- **No type switcher exists** in the builder (`form-field-type` is only written
  at creation), so a field's mapped Property datatype never has to change.
- Picture-choice is single-select only. A multi-select variant would have to
  change the mapped Property's datatype, which the builder can't do today.
- **`choice-matrix` and `table-input` share the `columns` options key** (plain
  labels vs `{label, type}` objects). Both readers normalize both shapes, so a
  hand-edited bag can't crash them.

## Tasks

- [x] `lib/defaults/forms.json` — extend the `form-field-type` enum docstring.
- [x] `docs/src/schema/forms.md` — a question-type table (datatype, options,
      submitted value) replacing the inline enum list.
- [x] `server/src/forms.rs` — `coerce_value` arms, `summarize_field` routing,
      empty-object handling, `rewrite_option_images` +
      `collect_option_image_subjects`, unit tests.
- [x] `server/src/handlers/form.rs` — `?file=` on `form_image` (gated, via a
      `FormImageQuery` extractor — `serde_urlencoded` can't flatten
      `DownloadParams`), option-image URL rewriting in `fill_image_url`.
- [x] `browser/form-renderer` — `types.ts`, `FieldInput.tsx`, `validation.ts`,
      `conditions.ts` (empty object/array), `style.css`.
- [x] `browser/data-browser/.../FormBuilder` — `fieldTypes.ts` (+
      `FIELD_TYPE_GROUPS`, now the single source of menu order), routing in
      `FieldSettingsPanel.tsx`, new `FieldOptions/*`, `buildFormDefinition.ts`,
      `ConditionsEditor.tsx` (`CHOICE_TYPES` / `NUMERIC_TYPES`).
- [x] Tests: Rust unit (`forms::`), server integration (`form_submission_flow`
      step 3d), e2e (`forms.spec.ts` every-type walk + a new
      `forms-submission.spec.ts` round-trip), `TESTING_COVERAGE.md` updated.

## Found along the way

- **Shared option-editor plumbing.** `FieldOptions/useFieldOptions.ts` (reads/
  writes the JSON bag, tolerating the raw-JSON-string rehydration hazard that
  bit `form-styling`) and `FieldOptions/StringListEditor.tsx` (debounced list
  editor, extracted from `ChoiceOptions`) back the new editors;
  `TextOptions`/`NumberOptions` were ported onto the hook too.
- **`build_block` now tolerates a string-materialized options bag**
  (`Ok(Value::String)` arm), matching `build_form_styling`.
- **Dropdown menus taller than the screen were unreachable (fixed).** 22 field
  types made the add-field menu taller than the viewport, and
  `components/Dropdown` placed it anyway — `overflow: auto` on the menu only
  scrolls what's inside the box, not the part hanging past the viewport, so the
  last items could not be clicked at all. It now measures the space above and
  below the trigger, opens on the side that fits, and caps `max-height` to the
  available room (minus a small margin) when neither side fits. Two subtleties:
  the cap must be cleared *before* measuring on reopen (measuring through a
  stale cap reports the clamped height, reads as "fits", and clears the cap —
  overflowing again), and this affects every long menu in the app, not just
  this one.
- **Rating radios carry their own `aria-label`** (`"4 out of 5"`) with the star
  glyph marked `aria-hidden`; labelling the glyph span instead left the inputs
  without accessible names.
- **Wuchale**: the new builder strings needed `pnpm exec wuchale`
  (data-browser). Non-English translations are left to the AI-translation flow
  (no `OPENROUTER_API_KEY` locally).
- **Human follow-up needed**: nothing schema-shaped — no new classes or
  properties were added, only new *values* of the existing unenforced
  `form-field-type` string and new keys inside the existing
  `form-field-options` JSON bag. So no atomicdata.dev ontology update and no
  `ATOMIC_REPOPULATE_DEFAULTS` restart is required for this change.
