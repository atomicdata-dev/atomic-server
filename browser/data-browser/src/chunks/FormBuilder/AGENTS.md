# Form builder

## Adding field settings

A field setting is not complete until the builder, form runtime, and AI tools
can read and write it consistently. Adding a control to the builder alone does
not expose the setting to the agent.

For settings stored in `form-field-options`:

1. Add the setting to the appropriate editor in `FieldOptions/`, the renderer's
   `FieldOptions` type in `browser/form-renderer/src/types.ts`, and any rendering
   or validation logic that consumes it. Update `FIELD_TYPE_DEFAULT_OPTIONS` in
   `fieldTypes.ts` when a default is needed. Keep preview and published behavior
   consistent: check `buildFormDefinition.ts` and `server/src/forms.rs` for Rust definition,
   coercion, and validation behavior.
2. Add an explicit, typed key to `formFieldOptionsSchema` in
   `formFieldOptionsSchema.ts`, with a description explaining its meaning,
   supported question types, units, and constraints. Ordinary optional settings
   should use `.nullable().optional()`: omission preserves the current value;
   `null` clears the setting. Do not replace this schema with an untyped JSON bag
   or silently accept unknown keys.
3. Add the key to each applicable type in `FORM_OPTION_KEYS` in the same file.
   This controls which types accept the setting and what `describe_form` lists
   in `availableOptions`.
4. Extend `applyFormFieldOptions` for constraints involving other settings or
   the mapped column. Validate the merged result, including retained values,
   before any resources are written. Preserve unrelated options and shared
   column constraints; presentation settings must not mutate a shared Property,
   class, or Tag.

`create_form` and `configure_form_field` already use this shared schema and
helper through `createFormFromSpec.ts` and `formOps.ts`. Updating the shared
schema exposes the option in both tools; do not duplicate its definition in
`../AI/useAtomicTools.ts`. Verify both creation and editing paths when changing
application logic. `describe_form` must return configured values and list applicable options
even when they have never been configured.

Settings stored outside `form-field-options` need explicit handling: update the
relevant tool input schema, validation, persistence, and description output in
`formOps.ts` and, if applicable, `createFormFromSpec.ts`. Update tool wrappers in
`../AI/useAtomicTools.ts` when arguments or subject-reference expansion change.
Use the dedicated choice operations for Tag creation/renaming; preserve existing
Tag subjects and past answers. Do not expose resolved options, storage datatype,
or borrowed choice sources as ordinary JSON settings without implementing their
resource relationships and shared-schema safeguards.

## Verification

- Extend `formFieldSettings.test.ts` for schema discoverability, creation and
  description round-trips, editing while retaining unrelated values, clearing
  with `null`, and invalid inputs rejected before writes. Include applicable
  type and shared-column constraints. Use `formOps.test.ts` for resource
  relationships and structural edits.
- Add renderer and/or Rust validation tests when the setting changes accepted
  answers or published behavior. Update the repository's `TESTING_COVERAGE.md`.
- Run the FormBuilder tests from `browser/data-browser` with
  `pnpm exec vitest run src/chunks/FormBuilder`, plus `pnpm typecheck` and lint
  for changed files. Follow the parent `AGENTS.md` for React compiler checks and
  visually verify changed UI controls.
