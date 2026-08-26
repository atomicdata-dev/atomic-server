# Form field shortnames — the Property's identifier is editable, `name` is gone

## Problem

A form field's Label is stored on the **FormField** (`name`). The mapped
**Property** got a *second* copy of that label in its own `name`, and its
`shortname` was slugified once, at creation, from the field type's default
label — then never touched again.

`useFormFieldPropertySync.renameField` synced only `name`, deliberately
("shortname is the stable technical identifier"). The result: a survey built by
picking six radio questions ends up with six Properties all shortnamed
`radio-group`, while their `name`s read fine. The shortname — the thing that
identifies the column in the data, and the thing `{{field-shortname}}` dynamic
text will key on (see [atomic-forms.md](./atomic-forms.md) Phase 7) — was
garbage, and duplicated.

## Decision

Form-builder-generated Properties carry **only a `shortname`**, no `name`.

- The label lives on the FormField, once. A Property `name` was always a copy
  that went stale the moment it disagreed.
- The shortname defaults to the sluggified label and **follows the label** for
  as long as it has not been customised.
- The user can override it in the field settings panel. An overridden shortname
  is pinned: later label edits leave it alone.
- Shortnames are made unique within the data class (`radio-group`,
  `radio-group-2`, …) instead of silently colliding.

Scope is the form builder only. `PropertyForm` / `NewPropertyDialog` and
hand-made table columns keep `name` as before.

Consequence, accepted: the Results tab's table headers come from
`useTitle(property)`, which now falls back to the shortname. A form column
header reads `whats-your-name`, not "What's your name?" — the header is exactly
the identifier the user edits in the panel. No prettifier, no form-specific
lookup in the generic table view.

## Auto vs. pinned, without a flag

No extra "isCustom" property. On rename, the previous shortname is compared
against the previous label:

```
isDerivedShortname(shortname, previousLabel)
  === stringToSlug(previousLabel)  ||  matches `<slug>-<n>`
```

If it matches, the shortname was auto-derived and gets re-derived from the new
label. If it doesn't, the user typed something and it stays. The `-<n>` arm is
what keeps de-duplicated slugs (`radio-group-2`) counting as auto-derived.

`base` is already a slug (`[a-z0-9-]`), so it needs no regex escaping.

## Work

- [x] `createSelectProperty.ts` — `createPropertyOnClass` /
      `createSelectPropertyOnClass` take a `PropertyNaming`: `name` (shortname
      slugified from it, as today) **or** a bare `shortname` for a property
      whose label lives elsewhere. `name` is written only when given.
- [x] `useFormFieldPropertySync.ts` — `createField` derives a unique shortname
      and passes no `name`; `renameField` re-derives the shortname when it is
      still auto-derived and strips a legacy `name`; new
      `setFieldShortname(field, shortname)` for the manual override, returning
      a collision/validation error instead of throwing.
- [x] `FieldSettingsPanel.tsx` — a **Data name** row under Label. Deliberately
      quiet: read-only monospace text with a pencil, styled as a caption rather
      than another labelled field, because for most questions the slug is
      derived and nobody needs to touch it. The pencil swaps the value for an
      input *in the same row* (same label, same height) so the panel doesn't
      shift; Enter or blur commits, Escape discards, a rejected slug stays in
      edit mode with its error underneath. Clearing it re-derives from the
      label. Input-type fields only (heading/paragraph have no mapped
      Property).
- [x] `e2e/tests/forms.spec.ts` — the property-sync spot check asserts
      `shortname`, not `name`; adds a manual-override case (pencil → type →
      Enter) and asserts the override survives a later label edit.

## Note on the read-only row

State resets on field switch come from `key={fieldSubject}` on the component,
not a `useEffect` — the effect version trips the React Compiler's
`set-state-in-effect` rule and costs the component its auto-memoization.

The helper sentence is written inline in the `title` attribute rather than
pulled out into a `const`: wuchale ignores module-level strings, so a hoisted
const would silently ship untranslated.
