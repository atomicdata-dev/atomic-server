# Min / max selections on multi-select questions — DONE

Let a form author bound how many options a visitor may tick on the two
multi-pick question types (`multi-select`, `dropdown-multi`).

## Decisions

- **Stored in the `form-field-options` bag** as `minSelected` / `maxSelected`,
  not on the mapped SelectProperty. Same call as `table-input`'s
  `minRows`/`maxRows`: the bound is a property of the *question*, not of the
  column the answers land in. (The property's own `max` stays what it is
  today: `1` for the single-pick types, unset otherwise. A results-table
  editor is therefore not bound by the form's limits — deliberate.)
- **Distinct keys, not `min`/`max`.** The bag is flat and `min`/`max` already
  mean "value bounds" on `number`/`currency` and "steps" on `rating`; a count
  bound reading the same key would be one copy-paste away from a wrong error
  message.
- **Max is enforced at input time, min only at validation time.** Past the
  maximum the remaining options go disabled (checkboxes and menu rows alike),
  which is the standard affordance and needs no error. A minimum can only be
  judged when the visitor is done, so it is a validation message.
- **A blank answer stays "unanswered", not "under the minimum".** `min` only
  applies to a non-empty answer; making a field mandatory is what `required`
  is for. Mirrors `table-input`, whose empty grid is empty rather than short.

## Tasks

- [x] `browser/form-renderer/src/types.ts` — the two option keys.
- [x] `validation.ts` — `selectionBounds()` + the count check in the
      `multi-select` / `dropdown-multi` arm; unit tests.
- [x] `FieldInput.tsx` / `SelectMenu.tsx` / `style.css` — disable past the
      max, hint line under the input.
- [x] `chunks/FormBuilder` — `BoundField` (shared numeric-bound editor,
      extracted from the three hand-rolled `setBound` copies), the min/max
      pair in `ChoiceOptions` for the multi types.
- [x] `server/src/forms.rs` — the same check in `coerce_value`, unit test.
- [x] `docs/src/schema/forms.md` — the two rows of the question-type table.
- [x] e2e: bounds set in the builder and enforced in the preview.
