import {
  canonicalizeScheme,
  core,
  forms,
  parseConstraints,
  Resource,
  setClassConstraint,
  Store,
  useResource,
  useStore,
} from '@tomic/react';
import { createMappedField } from './tableColumns';
import { useCallback } from 'react';
import {
  createPropertyOnClass,
  createSelectPropertyOnClass,
} from '../TablePage/Kanban/createSelectProperty';
import { stringToSlug } from '@helpers/stringToSlug';
import {
  carryValuesOver,
  createContentAddressedFromDraft,
  createPropertyDraft,
  isContentAddressed,
  replacePropertyReferences,
} from '@helpers/propertyIdentity';
import { DEFAULT_INFO_BOX_STYLE } from '@tomic/form-renderer';
import {
  DEFAULT_CHOICE_TAGS,
  FIELD_TYPE_DEFAULT_OPTIONS,
  FIELD_TYPE_TO_DATATYPE,
  isChoiceFieldType,
  isLayoutType,
  SINGLE_CHOICE_FIELD_TYPES,
  type AddableFieldType,
  type FormLayoutType,
} from './fieldTypes';

/** The class each layout block is created as. */
const LAYOUT_TYPE_CLASS: Record<FormLayoutType, string> = {
  heading: forms.classes.formHeading,
  paragraph: forms.classes.formParagraph,
  'info-box': forms.classes.formInfoBox,
};

interface CreateFieldOpts {
  type: AddableFieldType;
  label: string;
  existingProperty?: Resource;
  choices?: string[];
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

/**
 * Gives `to` the entry `from` has in the class's `constraints` map and drops
 * `from`'s. Does not save; the caller saves the class.
 */
async function moveClassConstraint(
  dataClass: Resource,
  from: string,
  to: string,
): Promise<void> {
  const raw = dataClass.get(core.properties.constraints);

  if (raw === undefined) {
    return;
  }

  const entry = parseConstraints(raw).get(canonicalizeScheme(from));

  if (!entry) {
    return;
  }

  await setClassConstraint(dataClass, to, entry);
  await setClassConstraint(dataClass, from, undefined);
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

/** Shared resource creation for the builder and AI tool. */
export async function createFormField(
  store: Store,
  dataClass: Resource,
  ownsSchema: boolean,
  page: Resource,
  opts: CreateFieldOpts,
): Promise<Resource> {
  let field: Resource;

  if (isLayoutType(opts.type)) {
    field = await store.newResource({
      parent: page.subject,
      isA: LAYOUT_TYPE_CLASS[opts.type],
      // A heading _is_ its title; a paragraph and an info box are their
      // body text. The info box's own (optional) title is left unset —
      // an untitled callout is a perfectly good one.
      propVals:
        opts.type === 'heading'
          ? { [core.properties.name]: opts.label }
          : opts.type === 'info-box'
            ? {
                [core.properties.description]: opts.label,
                [forms.properties.formInfoBoxStyle]: DEFAULT_INFO_BOX_STYLE,
              }
            : { [core.properties.description]: opts.label },
    });
    await field.save();
  } else if (opts.existingProperty) {
    field = await createMappedField(
      store,
      page,
      dataClass,
      opts.existingProperty,
    );
  } else {
    if (!ownsSchema) throw new Error('Add a column on the table first');
    const shortname = uniqueShortname(
      stringToSlug(opts.label),
      await takenShortnames(store, dataClass),
    );

    // A choice question's column is an ordinary enum column: a
    // SelectProperty whose Tags, listed in the `enum` of the data class's
    // constraint for it, *are* the question's options.
    // That is what gives form answers tag pills, colors and kanban
    // grouping, and what lets renaming an option leave past submissions
    // reading correctly.
    const propertySubject = isChoiceFieldType(opts.type)
      ? (
          await createSelectPropertyOnClass(store, dataClass, {
            shortname,
            tags: (opts.choices ?? DEFAULT_CHOICE_TAGS).map(name => ({
              name,
            })),
            // Options and the pick limit go to the data class's constraints
            // for the column (`enum`, `maxItems: 1`), not onto the Property.
            max: SINGLE_CHOICE_FIELD_TYPES.includes(opts.type) ? 1 : undefined,
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
}

/**
 * Keeps a Form's questions in sync with the generated data class: adding an
 * input field creates the mapped Property (via the same primitive Tables use
 * for columns), renaming a field changes the FormField's label only, and deleting a field only unlinks it — the Property
 * (and any data already collected for it) is left untouched.
 *
 * Form-generated Properties carry no `name`: the Label is the FormField's, and
 * `useTitle` falls back to the shortname, so the results table's column header
 * is exactly the identifier shown in the field settings panel. See
 * `planning/form-field-shortnames.md`.
 */
export function useFormFieldPropertySync(
  dataClassSubject: string,
  ownsSchema: boolean,
) {
  const store = useStore();
  const dataClass = useResource(dataClassSubject);

  const createField = useCallback(
    async (page: Resource, opts: CreateFieldOpts): Promise<Resource> => {
      return createFormField(store, dataClass, ownsSchema, page, opts);
    },
    [store, dataClass, ownsSchema],
  );

  /**
   * Renames a question. Only the FormField's label changes: the mapped
   * Property's shortname is part of its content-addressed ID and never
   * follows a rename. Use {@link setFieldShortname} to pick another one.
   */
  const renameField = useCallback(async (field: Resource, newLabel: string) => {
    await field.set(core.properties.name, newLabel);
    await field.save();
  }, []);

  /**
   * Overrides the mapped Property's shortname. Returns an error message when
   * the slug is empty or already used by another column of the data class, in
   * which case nothing is written.
   *
   * A content-addressed Property cannot be renamed, so this creates a sibling
   * with the new shortname, points the field and the data class at it and
   * leaves the old one behind. Legacy Properties are renamed in place.
   */
  const setFieldShortname = useCallback(
    async (field: Resource, shortname: string): Promise<string | undefined> => {
      const propertySubject = field.get(forms.properties.formMapsTo) as
        | string
        | undefined;

      if (!ownsSchema || !propertySubject) {
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

      if (!isContentAddressed(propertySubject)) {
        await property.set(core.properties.shortname, shortname);
        await property.save();

        return undefined;
      }

      const draft = await createPropertyDraft(
        store,
        property.get(core.properties.parent) as string,
        { source: property },
      );
      await draft.set(core.properties.shortname, shortname);
      const created = await createContentAddressedFromDraft(
        store,
        property.get(core.properties.parent) as string,
        draft,
      );
      // Answers already stored under the old Property show up under the new
      // one through a lens.
      await carryValuesOver(store, property, created);
      // The class's constraints (a choice question's options, its pick limit)
      // are keyed by Property, so they follow the question to the new one.
      await moveClassConstraint(dataClass, propertySubject, created.subject);
      await replacePropertyReferences(store, propertySubject, created.subject, [
        dataClass,
      ]);
      await field.set(forms.properties.formMapsTo, created.subject);
      await field.save();

      return undefined;
    },
    [store, dataClass, ownsSchema],
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
