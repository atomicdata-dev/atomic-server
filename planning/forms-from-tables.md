# Forms from existing tables

Goal: users can create a form from an existing table, and form inputs can map to
existing columns instead of always creating new ones.

## Current state

- Every `FormField` already carries `formMapsTo` → a Property subject, and
  submissions are plain rows of the table's class
  (`server/src/handlers/form.rs::submit_form`). The data model needs no changes.
- The only place that forces "new input = new column" is
  `browser/data-browser/src/chunks/FormBuilder/useFormFieldPropertySync.ts::createField`,
  which unconditionally calls `createPropertyOnClass` (from
  `chunks/TablePage/Kanban/createSelectProperty.ts`) and pushes the new Property
  onto the row class's `recommends` + the drive ontology.
- Table columns = the row class's `requires` + `recommends`
  (`chunks/TablePage/useTableColumns.tsx`). Per-view visibility/ordering lives on
  the View, not the class.
- Existing property-picker UIs to draw from:
  - `chunks/TablePage/PropertyForm/ExternalPropertyDialog.tsx` (ResourceSelector
    filtered to Property, pushes onto `recommends`) — closest model.
  - `views/OntologyPage/Class/AddPropertyButton.tsx` (SearchBox + inline create).
  - `views/CodeUsage/PropSelector.tsx` (simple select over a class's
    `requires + recommends`).
- Field type ↔ datatype map: `chunks/FormBuilder/fieldTypes.ts`
  (`FIELD_TYPE_TO_DATATYPE`).

## Mental model (decision)

A form is a **view over the table's columns** (Airtable/Notion model). The
table's class owns the schema; a form selects a subset of its columns and adds
presentation on top (question label, helper text, ordering, required-ness).
Every input maps to a column — no form-only fields.

## UX plan

### 1. "Add field" menu gets two sections

- [ ] Top section: connected table's columns not yet on the form, with type
      icons — one click adds a `FormField` with `formMapsTo` set to the existing
      Property (skip `createPropertyOnClass`).
- [ ] Bottom section: the current "new field" type list, unchanged — still
      creates a column immediately (matches table builder behavior).
- [ ] When adding an existing column, ensure the Property is on the data class's
      `recommends` if it isn't already (same as `ExternalPropertyDialog`).

### 2. "Create form from table" entry point

- [ ] Action on the table page: "Create form from this table". This is the
      **only** entry point for table-first forms — the generic "create form"
      dialog stays form-first (generates its own table) and gets no
      table-picker. Context does the work; matches Airtable/Notion.
- [ ] Creation dialog shows the table's columns as a checklist — pre-checked,
      minus computed/derived and row-action columns (those are view config, not
      Properties).
- [ ] Resulting form gets `formTargetTable` → the existing table and
      `formDataClass` → its existing `classtype`; skip the table-creation path
      in `NewFormDialog.tsx`.
- [ ] Parenting is the inverse of the form-first flow: `form.parent = table`
      (the pre-existing table keeps its own parent). The table view finds its
      forms by querying children with `isA Form` — no new backlink property.
      Safe because the table does NOT render all children as rows: the rows
      query constrains to `isA = classtype` (`useTableData.ts` `classFilter`),
      added precisely because View resources are already non-row children of
      the table. Totals share the same `queryFilters`. Forms are excluded the
      same way Views are.
- [ ] Cascade delete: deleting the table deletes its child forms. That's
      correct (a form can't function without its target table), but the
      delete-table confirmation must mention attached forms.
- [ ] Table toolbar gets a "Forms" affordance listing linked forms + "New
      form from this table". Table-first forms do NOT appear top-level in the
      sidebar; the toolbar (and search) is how you get back to them. Supports
      multiple forms per table.
- Deliberate asymmetry: form-first → form in sidebar, generated table nested
  under it (current); table-first → table in sidebar, form nested under it.
  The sidebar shows whichever object the user created as "the thing". If
  tucked-away forms prove hard to rediscover, a drive-level "all forms"
  collection is a cheap later fix — not designed for now.

### 3. Decouple question label from column name

- [ ] Give `FormField` its own label property; the form never renames the
      mapped Property. **This fixes a bug-in-waiting:** `renameField` currently
      renames the mapped Property unconditionally, which is destructive once
      columns are shared (two forms on one table, or a hand-built table).
- [ ] Show the mapped column as a small read-only chip in
      `FieldSettingsPanel.tsx`.
- [ ] New ontology bits go in `lib/defaults/forms.json` + `populate_default_store`
      + `urls.rs` + the TS mirror `browser/lib/src/ontologies/forms.ts`.

### 4. Field type derived from column datatype

- [ ] Invert `FIELD_TYPE_TO_DATATYPE` when adding an existing column.
- [ ] Where multiple input types share a datatype (string → short-text /
      long-text / email / radio), let the user pick among only the compatible
      ones. No free type switching — the datatype is fixed by the column.

### 5. Explicit removal language

- [ ] "Remove from form" = unlink/destroy the FormField only (current delete
      behavior, keep it).
- [ ] Separate, clearly-scarier "Delete column from table" with a warning that
      it affects the table and existing data. Default action never mutates the
      table.

### 6. Respect `requires`

- [ ] If a mapped column is in the class's `requires`, force the field to
      required in the builder (or warn).
- [ ] Warn when a `requires` column is left off the form — server-side row
      creation will be missing it.

## Deliberate non-goals

- No form-only fields (answers stored outside the table). Every input maps to a
  column; Results/Summary machinery assumes rows.
- No auto-sync of new table columns into existing forms. They appear in the
  "available columns" section of the add menu; at most a subtle "N unused
  columns" hint in the builder. Nothing silently appears on a published form.
- No editing a reused column's datatype/select-options from the form builder
  without making it obvious it edits the table's schema. Options editing is fine
  for a select the form itself created; for shared columns, link out or label
  the section "Table column settings".

## Open questions

- Should a new field created in the form add its column immediately (current)
  or only on publish? Leaning **immediate** — matches table builder, keeps
  `recommends`/ontology consistent; draft forms with stray columns are a
  smaller problem than a divergent staging model.

## Testing notes

- Server validation (`server/src/forms.rs::validate_submission`) rejects values
  whose key isn't a known `formMapsTo`, so reused columns must round-trip
  through it — cover with a submission test against a form built on a
  pre-existing table.
- E2E: `browser/e2e/tests/forms.spec.ts` / `forms-submission.spec.ts` are the
  existing suites; add a "form from existing table" spec. Update
  `TESTING_COVERAGE.md`.
