# Forms from existing tables

Goal: users can create a form from an existing table, and form inputs map to
that table's existing columns.

Reviewed 2026-09-08 against the `forms-#875` branch. Sections that were
already done (or overtaken by later forms work) are folded into "Current
state"; the remaining plan is below.

## Current state

- Every `FormField` carries `formMapsTo` → a Property subject, and
  submissions are plain rows of the table's class
  (`server/src/handlers/form.rs::submit_form`). The data model needs no changes.
- **Label is already decoupled from the column** (commit `f3d3a29b0`,
  `planning/form-field-shortnames.md`). The `FormField`'s own `name` is the
  question label; the mapped Property carries only a `shortname`. The panel
  shows that shortname as a quiet read-only "Data name" row with a pencil
  (`FieldSettingsPanel.tsx::FieldShortnameField`). The old plan's "give
  FormField its own label property" and "show the column as a chip" are
  done in spirit — but see the caveat under "Shared columns" below: the
  sync hook still *writes* to the Property.
- Field creation is the only place that forces "new input = new column":
  `chunks/FormBuilder/useFormFieldPropertySync.ts::createField` always calls
  `createPropertyOnClass` / `createSelectPropertyOnClass`
  (`chunks/TablePage/Kanban/createSelectProperty.ts`) and pushes the new
  Property onto the row class's `recommends` + the drive ontology.
- `deleteField` already only unlinks: it destroys the FormField (+ its
  conditions) and leaves the Property and data alone. The row button is still
  titled "Delete field" (`FieldRow.tsx`).
- Choice questions are SelectProperty columns with Tag options
  (`planning/form-choice-options-as-resources.md`), and a question can
  *borrow* options from another table's column or rows
  (`FieldOptions/optionsSource.ts`, `LinkOptionsDialog.tsx`). That is
  "reference another table's data", not "map to another table's column" —
  the response column is still form-owned.
- Table columns = the row class's `requires` + `recommends`
  (`chunks/TablePage/useTableColumns.tsx`). Per-view visibility/ordering lives
  on the View, not the class.
- The Form class **requires** `formDataClass`, `formTargetTable` and
  `formPages` in its genesis commit (`lib/defaults/forms.json`), which is why
  `NewFormDialog.tsx` creates the table first and re-parents it afterwards.
- Deleting a Form goes through `DeleteFormDialog.tsx` (registered in
  `customDeleteDialogs.ts`): keeps the table by default, with an opt-in
  cascade that destroys rows + table. `Resource.destroy()` never cascades.
- Sidebar: a Form hides its children (`ResourceSideBar.tsx`); a Table hides
  its children too. Table rows are constrained by `isA = classtype`
  (`useTableData.ts` `classFilter`), so non-row children of a table (Views,
  and later Forms) never show up as rows.
- Existing property-picker UIs to draw from:
  - `chunks/TablePage/PropertyForm/ExternalPropertyDialog.tsx` (ResourceSelector
    filtered to Property, pushes onto `recommends`).
  - `views/OntologyPage/Class/AddPropertyButton.tsx` (SearchBox + inline create).
  - `views/CodeUsage/PropSelector.tsx` (simple select over a class's
    `requires + recommends`).
- Field type ↔ datatype map: `chunks/FormBuilder/fieldTypes.ts`
  (`FIELD_TYPE_TO_DATATYPE`). Keep in lockstep with `@tomic/form-renderer`'s
  `FieldType` and `coerce_value` in `server/src/forms.rs`.

## Mental model (decision)

A form is a **view over the table's columns** (Airtable/Notion model). The
table's class owns the schema; a form selects a subset of its columns and adds
presentation on top (question label, helper text, ordering, required-ness).
Every input maps to a column — no form-only fields.

Two kinds of form, decided by how it was created, stored as one bit on the
Form (see "Ontology" below):

| | form-first (current) | table-first (this plan) |
| --- | --- | --- |
| who owns the schema | the form; it generated the class | the table; it existed before the form |
| add field menu | new-field type list (creates a column) | **existing columns only** |
| rename / data name | rewrites the Property's shortname | never touches the Property |
| delete field | unlink FormField | unlink FormField |
| sidebar | form top-level, table nested under it | table top-level, form nested under it |

**Decision (2026-09-08): table-first forms cannot create new fields.** The
add menu lists only the table's unused columns. To add a question that has no
column yet, the user adds the column on the table and then adds it to the
form. Reasons: one place owns the schema; the builder never has to decide
whether a rename/option-edit is safe for a column it did not create; no
"whose column is this" split in the menu; and it matches how people already
think about a table they built by hand. A "Add a column to the table" link
from the empty add-menu state is enough of a shortcut.

## Shared columns: what the builder must stop doing

Everything in `useFormFieldPropertySync.ts` beyond `createField` assumes the
form owns the Property. On a table-first form each of these is destructive
to the table:

- `renameField` re-derives the Property `shortname` when it still looks
  derived from the old label. A hand-built column's shortname is part of the
  table's schema; a form must not rewrite it.
- `setFieldShortname` writes the Property `shortname`.
- `ChoiceOptions` / `LinkableTagList` edit the mapped SelectProperty's Tags in
  place; `applyOptionsSource` / `clearOptionsSource` rewrite its `isA`,
  `classtype` and `allowsOnly`.

Rule: on a table-first form the hook is read-only towards the Property. Label
edits stay on the FormField; the "Data name" row is read-only (no pencil);
the options section shows the column's Tags read-only with a "Edit column on
table" link; the "Link options to a table" action is hidden. This is the
existing "No editing a reused column's datatype/select-options" non-goal,
made concrete.

## Ontology

- [ ] Add a boolean `form-owns-schema` (name TBD) to `Form.recommends`.
      `NewFormDialog` (form-first) sets it `true`; the table-first entry point
      leaves it unset/false. Read once in `FormBuilderPage` and passed down;
      every "may I write to the Property" decision keys on it. Goes in
      `lib/defaults/forms.json` + `populate_default_store` + `urls.rs` + the TS
      mirror `browser/lib/src/ontologies/forms.ts`.
- No backlink from table to form. The table finds its forms by querying
  children with `isA Form`.

## Plan

### 1. "Create form from this table" entry point

- [ ] Action on the table page (toolbar / view tabs area): "Create form from
      this table". This is the **only** entry point for table-first forms —
      the generic "create form" dialog stays form-first and gets no
      table-picker.
- [ ] Creation dialog: form name + the table's columns as a checklist,
      pre-checked, minus derived/computed and row-action columns (view
      config, not Properties). Each checked column becomes a `FormField` on
      the starter page (see §2 for the mapping).
- [ ] Resulting form: `formTargetTable` → the table, `formDataClass` → its
      `classtype`, `formPages` → one starter page, `form-owns-schema` unset.
      Both required subjects already exist, so no re-parenting dance.
- [ ] `form.parent = table`. Safe: the rows query is filtered by
      `isA = classtype` (`useTableData.ts`), totals share the same
      `queryFilters`, and the sidebar hides a table's children anyway.
- [ ] Table page gets a "Forms" affordance listing linked forms (children
      with `isA Form`) + "New form from this table". This, and search, is how
      you get back to a table-first form; it is not top-level in the sidebar.
      Supports multiple forms per table.
- [ ] Deleting a table currently orphans nothing visible because
      `destroy()` doesn't cascade — but a form whose target table is gone is
      dead. The table delete confirmation must mention attached forms and
      destroy them (or their FormFields at least). `DeleteFormDialog` needs no
      change for table-first forms: its cascade option is the wrong offer
      there, so hide "also delete the table" when `form-owns-schema` is false.

### 2. Add-field menu on a table-first form

- [ ] `AddFieldMenu` takes a mode. Table-first: list the row class's
      `requires + recommends` minus columns already on *any* page of the form
      (`useFormQuestions` gives the mapped subjects), each with the icon of
      its derived field type. One click creates a `FormField` with
      `formMapsTo` set to the existing Property — `createField` grows an
      `existingProperty` branch that skips `createPropertyOnClass`.
- [ ] Layout blocks (heading / paragraph / info box) stay available in both
      modes; they have no column.
- [ ] Empty state when every column is on the form: "All columns are on this
      form. Add a column to the table to ask something new." with a link to
      the table.
- [ ] Field label defaults to the Property's `name` (fallback shortname).
      `required` defaults to whether the column is in `requires`.
- [ ] Derive the field type from the column: invert `FIELD_TYPE_TO_DATATYPE`,
      then narrow by shape — a SelectProperty is `dropdown` (`max: 1`) or
      `dropdown-multi`; a relation column (`classtype`, no `allowsOnly`) is a
      `dropdown` with a rows `optionsSource` on the target table; `STRING` →
      `short-text`; `FLOAT` → `number`; `INTEGER` → `number`; `JSON` → not
      offered (no way to know if it is a matrix/table/address); `FILE`,
      `LOCALIZEDTEXT`, unknown datatypes → not offered, listed greyed-out with
      "not supported in forms".
- [ ] Where several types share a datatype, let the user switch among the
      compatible ones only (string → short-text / long-text / email / phone /
      url / country; float → number / currency; integer → number / likert /
      rating; select → dropdown / radio / picture-choice or dropdown-multi /
      multi-select). Type switching is presentation, the column is fixed.

### 3. Builder is read-only towards shared columns

- [ ] `useFormFieldPropertySync` takes `ownsSchema`. When false: `renameField`
      only sets the FormField `name`; `setFieldShortname` is not offered;
      `deleteField` unchanged.
- [ ] `FieldSettingsPanel`: "Data name" row without the pencil; a
      "Table column" line linking to the column (opens `EditPropertyDialog`
      on the table, or the table page with the column highlighted).
- [ ] `ChoiceOptions`: read-only tag list + "Edit column on table" link; no
      "Link options to a table" button. Selection bounds (`minSelected` /
      `maxSelected`) stay editable — they are form presentation, but must not
      exceed the column's own `max`.
- [ ] Type-specific option panels that only touch `form-field-options`
      (placeholder, length bounds, likert labels, …) stay editable; they never
      reach the Property.

### 4. Removal language

- [ ] Rename the row button to "Remove from form" in both modes — that is
      what it already does.
- [ ] No "Delete column from table" action in the builder. Column deletion
      lives on the table, where the data is visible.

### 5. Respect `requires`

- [ ] A field mapped to a `requires` column is forced required (switch
      disabled, with a hint).
- [ ] Warn in the builder when a `requires` column is not on the form — the
      server rejects row creation without it. Cheap to compute from
      `useFormQuestions` vs. `rowClass.requires`.

## Deliberate non-goals

- No form-only fields (answers stored outside the table). Every input maps to a
  column; Results/Summary machinery assumes rows.
- No new columns from a table-first form (decision above).
- No auto-sync of new table columns into existing forms. They appear in the
  add menu; at most a subtle "N unused columns" hint. Nothing silently appears
  on a published form.
- No editing a shared column's datatype/options from the builder (§3).
- No conversion between form-first and table-first after creation.

## Testing notes

- Server: `validate_submission` rejects values whose key isn't a known
  `formMapsTo`, so reused columns must round-trip through it — add a
  submission test against a form whose fields map to a pre-existing class's
  properties (no form-generated Property), including a `requires` column and
  a hand-made SelectProperty with `name`d Tags.
- Unit (vitest): datatype → field type derivation, and the "compatible types"
  narrowing.
- E2E: `browser/e2e/tests/forms.spec.ts` / `forms-submission.spec.ts` are the
  existing suites. Add one "form from existing table" spec: create a table
  with a text, number, select and required column → create form from it →
  assert the add menu offers only the remaining column and no type list →
  rename a field and assert the Property `name`/`shortname` are untouched →
  publish and submit → row appears in the original table.
- Update `TESTING_COVERAGE.md` (§Forms).
