# Class constraints, and what they mean for forms

**Status:** Proposal (2026-10-08). Follows the schema API proposal that
replaces #2045's frozen app schemas: properties become immutable and
content-addressed, classes and ontologies stay owned and editable. Proposal doc:
https://claude.ai/code/artifact/275a9139-d8a6-49dd-ac55-8d3f5b5d9130

## Decision this depends on

A property's identity covers only its ontology, shortname and datatype. Every
other constraint moves to the class, the way JSON Schema puts `enum`,
`minimum` and `$ref` inside an object's `properties` entry instead of on a
global property. Joep chose JSON Schema's conventions over ShEx's on
2026-10-08; on this point both agree.

A class gets a constraints map: property ID to a subset of JSON Schema
keywords.

```json
{
  "<status property>": { "enum": ["<tag>", "<tag>"], "maxItems": 1 },
  "<amount property>": { "minimum": 0, "maximum": 10000 },
  "<customer property>": { "class": "<Customer class>" }
}
```

Keywords: `enum`, `minimum`, `maximum`, `exclusiveMinimum`,
`exclusiveMaximum`, `minLength`, `maxLength`, `minItems`, `maxItems`,
`pattern`, and `class` for the linked class (JSON Schema's `$ref`).
`requires` and `recommends` stay as they are (JSON Schema's `required`).

## Why forms care

Forms map each question to a column: a Property on the table's class
(`FORM_DATA_CLASS`). Today:

| Form concept | Stored on | Code |
| --- | --- | --- |
| Required | class `requires` | `server/src/forms.rs` `build_form_definition` |
| Choice options | Property `allowsOnly` (Tags) | `forms.rs` `tag_options`, `FieldOptions/ChoiceOptions.tsx`, `optionsSource.ts` |
| Single pick | Property `max: 1` | `forms.rs` `SINGLE_CHOICE_FIELD_TYPES` |
| Column limit | Property `max` | `ChoiceOptions.tsx` (`columnMax`) |
| Linked rows | table `classtype` | `forms.rs` `row_options` |
| Field limits (`min`, `max`, `minLength`, `maxLength`, `minSelected`, `maxSelected`, `minRows`, `maxRows`) | `form-field-options` JSON | `formFieldOptionsSchema.ts`, `form-renderer/src/validation.ts` |

With immutable properties, anything stored on the Property can no longer
change. Adding a choice would mint a new property and split old answers from
new ones. Moving these to the class constraints map keeps every edit a class
edit:

- **Choice options:** `allowsOnly` on the Property becomes `enum` in the class
  map. Adding, removing or renaming a choice edits the class (or the Tag, for a
  rename). Answers keep pointing at the same property and Tags.
- **Single pick and column limit:** `max` on the Property becomes `maxItems`
  in the class map.
- **Linked rows:** `classtype` becomes `class` in the class map.
- **Required:** unchanged.

## One validation vocabulary

The form's own limits are JSON Schema keywords under other names. Use one set:

- The class map is what every write must satisfy, from any app.
- A form's options may only tighten it for answers to that form
  (`minSelected` becomes `minItems`, and so on). `applyFormFieldOptions`
  already checks a form option against the column limit; that becomes the
  general rule.
- `forms.rs`, `form-renderer/src/validation.ts` and `atomic_lib` validate with
  the same rules. Ideally one Rust implementation, exposed to the renderer
  through WASM.

A form then has a JSON Schema for free: the class schema narrowed by the form.
`describe_form` can return it, and a published form can expose it for API
submissions and outside validators.

## Changing a question after answers exist

- Renaming a question edits a label. Free.
- Changing a question's type changes the datatype, so it becomes a new
  property. The old answers stay readable through a lens (proposal doc,
  "Schema change without breaking anyone"). The builder should say so when the
  form has answers.

## Scope beyond forms

`allowsOnly`, `max` and `classtype` on Properties are used well outside forms:
46 non-test files, including the table and kanban views
(`TablePage/Kanban/createSelectProperty.ts`, `PropertyForm`), the ontology
editor (`views/OntologyPage/Property`), resource selectors, `lib/src` validation
and `@tomic/lib`. A SelectProperty in this codebase is a property with
`allowsOnly`, so this is an app-wide change, not a forms change.

## Where this lands

Not in #2045. That PR is already too large to review, and it builds the
frozen app schema API the proposal drops. This is its own PR, after the hash
spec and before forms or kanban grow more users:

1. Class constraints map in `atomic_lib` and `@tomic/lib`, with validation on
   write. Read `allowsOnly`, `max` and `classtype` from the Property as a
   fallback for existing data.
2. Table, kanban and ontology editor write to the class map. **Done** for new
   data: `getEffectiveConstraint` / `useEffectiveConstraint` read the class map
   with the Property as per-keyword fallback; tables, kanban, the ontology
   class card and `InputSwitcher` use them. Forms still read the Property.
3. Forms read and write the class map; form options become tightenings.
   **Done**: the builder writes choice options (`enum`), the single pick
   (`maxItems: 1`) and a row link (`class`) to the form's data class and reads
   them through `getEffectiveConstraint` (Property fallback stays). A form's
   own limits use the keywords (`minimum`, `maximum`, `minLength`, `maxLength`,
   `minItems`, `maxItems`; old names still read) and may only tighten the class
   (`FormBuilder/formConstraints.ts`). `server/src/forms.rs` resolves options
   and narrows the limits with `atomic_lib::class_constraints::effective_constraint`
   when it builds the definition, so the renderer and the submit path validate
   the same keywords. `describe_form` returns the form's JSON Schema as
   `schema`. The renderer mirrors the keyword checks instead of importing
   `@tomic/lib` or WASM (it has no dependencies by design).
4. Drop the Property fallback once existing drives are converted.

Forms are not in production yet (`form-choice-options-as-resources.md`), so
forms need no answer migration. Existing tables with SelectProperty columns
do, which is step 4.

## Open questions

- [ ] A Property used by two classes keeps one Tag list today. After the move,
      each class has its own `enum`. Is that wanted, or should a class be able
      to say "same options as class X"?
- [ ] Do Tags stay resources (needed for colors, emoji, kanban) with `enum`
      listing Tag IDs? Assumed yes.
- [ ] Does `class` also allow several classes (JSON Schema `anyOf` of `$ref`)?
      Assumed no for now.
