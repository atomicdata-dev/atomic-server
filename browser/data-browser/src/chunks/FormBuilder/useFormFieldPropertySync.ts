import { core, forms, Resource, useResource, useStore } from '@tomic/react';
import { useCallback } from 'react';
import { createPropertyOnClass } from '../TablePage/Kanban/createSelectProperty';
import {
  FIELD_TYPE_DEFAULT_OPTIONS,
  FIELD_TYPE_TO_DATATYPE,
  isLayoutType,
  type AddableFieldType,
} from './fieldTypes';

interface CreateFieldOpts {
  type: AddableFieldType;
  label: string;
}

/**
 * Keeps a Form's questions in sync with the generated data class: adding an
 * input field creates the mapped Property (via the same primitive Tables use
 * for columns), renaming a field mirrors the rename onto the Property, and
 * deleting a field only unlinks it — the Property (and any data already
 * collected for it) is left untouched.
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
        const propertySubject = await createPropertyOnClass(
          store,
          dataClass,
          {
            name: opts.label,
            datatype: FIELD_TYPE_TO_DATATYPE[opts.type],
          },
        );

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
      await field.set(core.properties.name, newLabel);
      await field.save();

      const propertySubject = field.get(forms.properties.formMapsTo) as
        | string
        | undefined;

      if (propertySubject) {
        const property = await store.getResource(propertySubject);
        await property.set(core.properties.name, newLabel);
        // Deliberately not touching `shortname` — it's the stable technical
        // identifier (mirrors row/column shortnames elsewhere never being
        // re-slugged on rename); `name` is what's user-facing everywhere.
        await property.save();
      }
    },
    [store],
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

      // The mapped Property (and any submissions already written to it) is
      // deliberately left in place — only the FormField / form-maps-to link
      // is removed.
      await field.destroy();
    },
    [],
  );

  return { createField, renameField, deleteField };
}
