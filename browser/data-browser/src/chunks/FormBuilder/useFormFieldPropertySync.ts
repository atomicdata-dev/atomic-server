import {
  core,
  forms,
  Resource,
  Store,
  useResource,
  useStore,
} from '@tomic/react';
import { useCallback } from 'react';
import {
  createPropertyOnClass,
  createSelectPropertyOnClass,
} from '../TablePage/Kanban/createSelectProperty';
import { stringToSlug } from '@helpers/stringToSlug';
import {
  DEFAULT_CHOICE_TAGS,
  FIELD_TYPE_DEFAULT_OPTIONS,
  FIELD_TYPE_TO_DATATYPE,
  isChoiceFieldType,
  isLayoutType,
  SINGLE_CHOICE_FIELD_TYPES,
  type AddableFieldType,
} from './fieldTypes';

interface CreateFieldOpts {
  type: AddableFieldType;
  label: string;
}

/** The shortname a field falls back to when its label slugifies to nothing
 * (a label of only emoji or punctuation). */
const FALLBACK_SHORTNAME = 'field';

/**
 * Every shortname already in use by a property of `dataClass`, so a new
 * field's slug can be made unique. `except` is the property being renamed —
 * its own current shortname must not count as taken.
 */
async function takenShortnames(
  store: Store,
  dataClass: Resource,
  except?: string,
): Promise<Set<string>> {
  const subjects = [
    ...((dataClass.get(core.properties.requires) as string[] | undefined) ??
      []),
    ...((dataClass.get(core.properties.recommends) as string[] | undefined) ??
      []),
  ];

  const taken = new Set<string>();

  for (const subject of subjects) {
    if (subject === except) {
      continue;
    }

    const property = await store.getResource(subject);
    const shortname = property.get(core.properties.shortname) as
      | string
      | undefined;

    if (shortname) {
      taken.add(shortname);
    }
  }

  return taken;
}

/** `base`, or `base-2` / `base-3` / … if that is already taken. */
function uniqueShortname(base: string, taken: Set<string>): string {
  const root = base || FALLBACK_SHORTNAME;

  if (!taken.has(root)) {
    return root;
  }

  let suffix = 2;

  while (taken.has(`${root}-${suffix}`)) {
    suffix++;
  }

  return `${root}-${suffix}`;
}

/**
 * Whether `shortname` still looks like it was derived from `label` — i.e. the
 * user has not overridden it in the field settings panel, so a rename may
 * re-derive it.
 *
 * The `-<n>` arm is what keeps a de-duplicated slug (`radio-group-2`) counting
 * as auto-derived. `base` is already a slug (`[a-z0-9-]`), so it carries no
 * regex metacharacters and needs no escaping.
 */
export function isDerivedShortname(shortname: string, label: string): boolean {
  const base = stringToSlug(label) || FALLBACK_SHORTNAME;

  return shortname === base || new RegExp(`^${base}-\\d+$`).test(shortname);
}

/** Drops the label copy a form-generated Property used to carry. The Label
 * lives on the FormField; a second copy here only went stale. Returns whether
 * anything changed, so the caller can skip a needless save. */
function dropLegacyName(property: Resource): boolean {
  if (property.get(core.properties.name) === undefined) {
    return false;
  }

  property.remove(core.properties.name);

  return true;
}

/**
 * Keeps a Form's questions in sync with the generated data class: adding an
 * input field creates the mapped Property (via the same primitive Tables use
 * for columns), renaming a field re-derives the Property's shortname unless
 * the user pinned one, and deleting a field only unlinks it — the Property
 * (and any data already collected for it) is left untouched.
 *
 * Form-generated Properties carry no `name`: the Label is the FormField's, and
 * `useTitle` falls back to the shortname, so the results table's column header
 * is exactly the identifier shown in the field settings panel. See
 * `planning/form-field-shortnames.md`.
 */
export function useFormFieldPropertySync(dataClassSubject: string) {
  const store = useStore();
  const dataClass = useResource(dataClassSubject);

  const createField = useCallback(
    async (page: Resource, opts: CreateFieldOpts): Promise<Resource> => {
      let field: Resource;

      if (isLayoutType(opts.type)) {
        field = await store.newResource({
          parent: page.subject,
          isA:
            opts.type === 'heading'
              ? forms.classes.formHeading
              : forms.classes.formParagraph,
          propVals:
            opts.type === 'heading'
              ? { [core.properties.name]: opts.label }
              : { [core.properties.description]: opts.label },
        });
        await field.save();
      } else {
        const shortname = uniqueShortname(
          stringToSlug(opts.label),
          await takenShortnames(store, dataClass),
        );

        // A choice question's column is an ordinary enum column: a
        // SelectProperty whose `allowsOnly` Tags *are* the question's options.
        // That is what gives form answers tag pills, colors and kanban
        // grouping, and what lets renaming an option leave past submissions
        // reading correctly.
        const propertySubject = isChoiceFieldType(opts.type)
          ? (
              await createSelectPropertyOnClass(store, dataClass, {
                shortname,
                tags: DEFAULT_CHOICE_TAGS.map(name => ({ name })),
                max: SINGLE_CHOICE_FIELD_TYPES.includes(opts.type)
                  ? 1
                  : undefined,
              })
            ).subject
          : await createPropertyOnClass(store, dataClass, {
              shortname,
              datatype: FIELD_TYPE_TO_DATATYPE[opts.type],
            });

        field = await store.newResource({
          parent: page.subject,
          isA: forms.classes.formField,
          propVals: {
            [core.properties.name]: opts.label,
            [forms.properties.formMapsTo]: propertySubject,
            [forms.properties.formFieldType]: opts.type,
            [forms.properties.required]: false,
            [forms.properties.formFieldOptions]:
              FIELD_TYPE_DEFAULT_OPTIONS[opts.type],
          },
        });
        await field.save();
      }

      const currentFields =
        (page.get(forms.properties.formFields) as string[] | undefined) ?? [];
      await page.set(forms.properties.formFields, [
        ...currentFields,
        field.subject,
      ]);
      await page.save();

      return field;
    },
    [store, dataClass],
  );

  const renameField = useCallback(
    async (field: Resource, newLabel: string) => {
      const previousLabel =
        (field.get(core.properties.name) as string | undefined) ?? '';

      await field.set(core.properties.name, newLabel);
      await field.save();

      const propertySubject = field.get(forms.properties.formMapsTo) as
        | string
        | undefined;

      if (!propertySubject) {
        return;
      }

      const property = await store.getResource(propertySubject);
      const shortname = property.get(core.properties.shortname) as
        | string
        | undefined;

      let changed = dropLegacyName(property);

      // A shortname the user typed themselves is pinned — only one still
      // derived from the old label follows the rename.
      if (!shortname || isDerivedShortname(shortname, previousLabel)) {
        const next = uniqueShortname(
          stringToSlug(newLabel),
          await takenShortnames(store, dataClass, propertySubject),
        );

        if (next !== shortname) {
          await property.set(core.properties.shortname, next);
          changed = true;
        }
      }

      if (changed) {
        await property.save();
      }
    },
    [store, dataClass],
  );

  /**
   * Overrides the mapped Property's shortname. Returns an error message when
   * the slug is empty or already used by another column of the data class, in
   * which case nothing is written.
   */
  const setFieldShortname = useCallback(
    async (field: Resource, shortname: string): Promise<string | undefined> => {
      const propertySubject = field.get(forms.properties.formMapsTo) as
        | string
        | undefined;

      if (!propertySubject) {
        return undefined;
      }

      if (shortname === '') {
        return 'Required';
      }

      const taken = await takenShortnames(store, dataClass, propertySubject);

      if (taken.has(shortname)) {
        return 'Already used by another question';
      }

      const property = await store.getResource(propertySubject);
      dropLegacyName(property);
      await property.set(core.properties.shortname, shortname);
      await property.save();

      return undefined;
    },
    [store, dataClass],
  );

  const deleteField = useCallback(
    async (page: Resource, field: Resource) => {
      const currentFields =
        (page.get(forms.properties.formFields) as string[] | undefined) ?? [];
      await page.set(
        forms.properties.formFields,
        currentFields.filter(subject => subject !== field.subject),
      );
      await page.save();

      const conditions =
        (field.get(forms.properties.formConditions) as string[] | undefined) ??
        [];

      for (const subject of conditions) {
        const cond = await store.getResource(subject);
        await cond.destroy();
      }

      // The mapped Property (and any submissions already written to it) is
      // deliberately left in place — only the FormField / form-maps-to link
      // is removed.
      await field.destroy();
    },
    [store],
  );

  return { createField, renameField, setFieldShortname, deleteField };
}
