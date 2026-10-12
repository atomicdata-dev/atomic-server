# Form choice options as resources

Goal: choice questions (`radio`, `dropdown`, `multi-select`, `dropdown-multi`,
`picture-choice`) stop storing their options as a `string[]` in
`form-field-options` and instead use the table modeling the rest of the app
already has: a **SelectProperty** column whose `allowsOnly` lists **Tag**
resources.

Prerequisite for "options sourced from another table" (phase 2).

**No migration needed — forms are not in production.** One shape, no
back-compat shims, no two-shapes-forever.

## Current state

- `FIELD_TYPE_TO_DATATYPE` (`chunks/FormBuilder/fieldTypes.ts`) maps
  `dropdown`/`radio`/`picture-choice` → `STRING`, `multi-select`/`dropdown-multi`
  → `JSON`. Options live as `options: string[]` inside the
  `form-field-options` JSON bag.
- `useFormFieldPropertySync.ts::createField` calls `createPropertyOnClass`
  (plain, non-enum) for every input type.
- `createSelectPropertyOnClass` — in the *same file*
  (`chunks/TablePage/Kanban/createSelectProperty.ts`) — already does exactly
  what's needed and is used by kanban. The form builder just calls the wrong
  one of the two.
- A SelectProperty in this codebase is invariably
  `isA: [Property, SelectProperty]`, `datatype: RESOURCEARRAY`,
  `classtype: Tag`, `allowsOnly: [...]`
  (`PropertyForm/NewPropertyDialog.tsx`, `SelectPropertyForm.tsx`). Single-pick
  is expressed as `max: 1`, **not** a different datatype.
- `server/src/forms.rs::build_block` copies the options bag verbatim into the
  denormalized `FormDefinition` served to anonymous visitors.

## Why this is worth doing

1. **Renaming an option stops corrupting history.** Today options are strings
   copied into each row. Rename "Option 1" → "Yes" and past submissions still
   read "Option 1", `check_membership` starts *rejecting* the old value, and
   `choice_counts` grows a stale bucket. With references, rename is one write.
2. **A dropdown question produces a real enum column** — tag pills, colors,
   emoji, filters, and `view-group-by` (kanban grouping *requires* a
   SelectProperty). Today a form dropdown yields a plain string column you
   cannot kanban by.
3. **Answers become references.** This is what makes "pick one of my 400
   customers" a link to the customer row rather than a copied name string —
   and it collapses `dropdown`, `picture-choice`, and external sourcing into
   one mechanism.

## Decisions

- **All five choice types use `RESOURCEARRAY`.** Single-pick sets `max: 1` and
  stores a one-element array. Consistency with hand-made columns is what buys
  the kanban/tag-pill wins; a bespoke `ATOMIC_URL` single-select would look
  like a different kind of column to every existing table UI.
- **Tags carry a free-text `name`.** `Tag` only *requires* `shortname`, and
  `CreateTagRow` slugifies as you type — so tags are slug-labeled in practice.
  Form options need arbitrary text ("Strongly agree — I use it daily"), so
  seed `name` (label) alongside `shortname` (slug). `useTitle` already prefers
  `name`, so every existing tag renderer picks this up for free.
- **`optionImages` is deleted, not migrated.** Today it is a parallel array
  positionally matched to `options` — fragile. The image moves onto the option
  object.
- **The wire format carries resolved options.** An anonymous visitor has no
  agent and cannot fetch Tag resources, so `build_form_definition` resolves
  tags into inline option objects — the same denormalization
  `rewrite_option_images` already does for File subjects.

### Wire format

```ts
export interface FieldOption {
  value: string;   // Tag subject (or row subject, when table-sourced)
  label: string;   // resolved display text
  color?: string;
  emoji?: string;
  image?: string;  // picture-choice; replaces positional `optionImages`
}
```

`FieldOptions.options` becomes `FieldOption[]`. Conditions and summary counts
key on `value`; everything user-facing renders `label`.

## Phase 1 — the refactor

### Rust (`server/src/forms.rs`)

- [x] `build_block`: fetch the `form-maps-to` Property, read `allowsOnly`,
      resolve each Tag → `FieldOption`. Falls back to an empty list.
- [x] `check_membership`: options are objects now — compare against `.value`.
- [x] `coerce_value`: choice arms return `Value::ResourceArray`; single-pick
      arms enforce exactly one element.
- [x] `summarize_field` / `choice_counts`: key by subject, label from the
      resolved options.
- [x] `rewrite_option_images` / `collect_option_image_subjects`: read
      `option.image` instead of the `optionImages` array.
- [x] `is_empty_value`: an empty `ResourceArray` counts as unanswered.

### `@tomic/form-renderer`

- [x] `types.ts`: add `FieldOption`, retype `options`, drop `optionImages`.
- [x] `SelectMenu.tsx`: `SingleSelect` / `MultiSelect` take option objects.
- [x] `FieldInput.tsx`: the five choice cases; picture-choice reads
      `option.image`.
- [x] `validation.ts::checkMembership`, `conditions.ts`: compare on `value`.

### Builder (`chunks/FormBuilder`)

- [x] `fieldTypes.ts`: choice types → `RESOURCEARRAY`; default options seed
      tags rather than strings.
- [x] `useFormFieldPropertySync.ts`: choice types go through
      `createSelectPropertyOnClass` (+ `max: 1` for single-pick).
- [x] `ChoiceOptions.tsx` / `PictureChoiceOptions.tsx`: both now wrap a shared
      `TagListEditor`, which keeps `StringListEditor`'s familiar shape — one
      text input per option, remove beside each, add below — while each row
      edits a Tag's `name`. An earlier pass used the tag-pill editor
      (`CreateTagRow` + `EditableTag`, as `SelectPropertyForm` does) and it
      read as a different, heavier control for what is still just a list of
      labels. Picture-choice adds a thumbnail and image picker per row.
- [x] `ConditionsEditor.tsx`: `choiceOptions` becomes `{value,label}`; the
      picker shows labels and stores subjects.
- [x] `buildFormDefinition.ts`: mirror the tag resolution client-side so the
      preview matches what gets published.
- [x] `Summary/types.ts` + `ResultsTab.tsx`: no change needed —
      `choice_counts` matches picks by subject but keys the pairs by label, so
      the wire shape (`[label, count]`) and the results UI stayed as they were.

### Known gap to close

`max` is declared on `SelectProperty` (it is in the class's `recommends`) but
**not read anywhere** — `SelectCell.tsx` ignores it, so the table cell editor
will happily let you pick two tags in a `max: 1` column. Pre-existing, but
forms now depend on it meaning something.

- [x] Enforce `max` in `SelectCell`.

### Also done

- [x] `CreateTagRow` keeps the typed text as the Tag's `name` instead of
      slugifying it in the input; `shortname` gets the slug. Tags were
      slug-labeled everywhere before this.
- [x] `EditableTag`'s popover gained a rename field. Forms no longer need it
      (the option list edits names inline), but nothing anywhere could rename
      a tag before, so tables and ontologies keep the win.
- [x] `useDraftString` (`helpers/`): debounce **plus a flush on unmount**.
      A plain debounce drops the last edit whenever the input goes away inside
      the window — dismissing a popover, switching to another field. Both
      option-label inputs and the tag rename use it.
- [x] `SelectCell` prefers a tag's `name` over its `shortname` and filters
      case-insensitively on the label rather than on a slugified query.
- [x] e2e specs: the option-editing steps stayed on `choice-option-input`, but
      two *pre-existing* failures in `forms-submission.spec.ts` surfaced once
      the test got that far — `dropdown` is the `SelectMenu` combobox rather
      than a native `<select>` (broken by ca0ae4c4), and the address's country
      subfield is a `CountrySelect`, so neither took `selectOption`/`fill`.

### Tests

- [x] `server/src/forms.rs`: `dropdowns_enforce_option_membership` and the
      other choice-type submission tests move to subjects.
- [x] `form-renderer`: `validation.test.ts`, `conditions.test.ts`.
- [x] Update `TESTING_COVERAGE.md`.

## Phase 2 — options from another table

Two sourcing modes, stored on `form-field-options` as `optionsSource`. Which
one applies is decided by *which column you pick*, so the builder asks one
question ("table + column") rather than making you choose a mode first:

- [x] `{ table, property }` — the picked column is a **SelectProperty**, so
      its `allowsOnly` Tags are the options. Resolution is identical to phase
      1 (`tag_options`); only where the list is read from changes. The tags are
      also mirrored onto the field's own Property so the response column still
      works standalone in the table UI.
- [x] `{ table, labelProperty }` — the picked column is anything else, so the
      table's **rows** become the options, labelled by that column and
      resolved per definition GET (`row_options`). The field's Property drops
      `SelectProperty`/`allowsOnly` and becomes a plain relation column
      (`classtype` = the table's row class).

`table` is stored in both cases (it is what the builder picked first);
resolution ignores it when `property` is set.

Nothing downstream of resolution changed: `check_membership`, `coerce_value`
and `choice_counts` already key on the resolved `FieldOption.value`, which is a
row subject just as readily as a tag subject.

### Builder

- [x] A link button beside the **Options** label, in both states
      (`LinkableTagList`). It opens `LinkOptionsDialog`: a table picker
      (`ResourceSelector` filtered to `Table`) and then a radio list of that
      table's columns, each saying what picking it would do.
- [x] Linked questions replace the option rows + "Add option" with
      `LinkedOptions` — "Linked to *Column* in *Table*", a line explaining
      which mode it is in, and **Unlink**.
- [x] `applyOptionsSource` / `clearOptionsSource` / `syncMirroredTags`
      (`optionsSource.ts`) own every write to the mapped Property. Linking
      destroys the Tags the question had made for itself (they are parented
      under its Property and nothing else can reach them); unlinking leaves an
      empty enum column rather than keeping the borrowed tags, which would let
      an edit here rename a tag on the other table.
- [x] `buildFormDefinition.ts` mirrors both resolution paths so the preview
      matches what gets published.
- [x] A freshly created choice question no longer seeds two placeholder
      options. Every option is a real Tag resource, and linking deletes them
      anyway — so the builder stops creating resources nobody asked for.

### Phase 2 caveats

- **Exposure.** Row-sourced options publish every row label in that column to
  anonymous visitors — `row_options` runs as `ForAgent::Sudo` precisely because
  the visitor has no agent. Deliberate (same tradeoff as publish-gated cover
  images); the dialog shows a `WarningBlock` naming the table as soon as you
  pick a non-tag column.
- **Cost.** A row scan per definition GET, and `/form/{id}` injects the
  definition into the HTML on every page load. Capped at `OPTIONS_ROW_LIMIT`
  (1,000 — smaller than `SUMMARY_ROW_LIMIT`, since this list is a picker, not
  an aggregate). No cache yet; if this shows up in a trace, a short TTL on the
  resolved definition is the obvious next step.
- **Truncation is silent.** A pick past the cap is rejected by
  `check_membership` with a generic "not one of the allowed options".
- **A row the label column is empty for is not an option.** `row_label` /
  `rowLabel` return no label rather than falling back to the row's `name`: the
  fallback put a *different* column's text in the list for exactly the rows the
  picked column was blank for, which reads as a bug and differs between the
  preview and the published form. Composite values (a relation, a nested
  resource, JSON) count as absent for the same reason — no one-line rendering.
  So a table whose picked column is empty everywhere offers nothing, which is
  the honest answer.
- **The mirror can drift.** `syncMirroredTags` refreshes the response column
  when the field's settings panel opens, so a tag added on the source table
  shows up there — but only then. The *published* options never drift; they
  always resolve from the source.
- **Conditions on a row-sourced question** get a free-text value input rather
  than a picker (`useFormQuestions` resolves options from the mapped
  Property's `allowsOnly`, which row-sourced questions do not have).

### Tests

- [x] `server/src/forms.rs`: `choice_options_can_mirror_another_columns_tags`,
      `choice_options_can_be_the_rows_of_a_table`,
      `an_unresolvable_options_source_allows_nothing`.
- [x] e2e: `forms.spec.ts` / `forms-submission.spec.ts` now add their own
      options instead of relabelling the two that used to be seeded.
- [x] `TESTING_COVERAGE.md` — including what phase 2 leaves untested (the
      whole builder side, the client mirror, and the row cap).

## Relationship to other plans

- [form-field-types.md](./form-field-types.md) — the extended field-type set
  these five choice types come from.
