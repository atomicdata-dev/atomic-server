// @wc-ignore-file
import {
  core,
  dataBrowser,
  forms,
  type Resource,
  type Store,
} from '@tomic/react';
import { z } from 'zod';
import {
  formFieldOptionsSchema,
  applyFormFieldOptions,
} from './formFieldOptionsSchema';
import {
  createRowClass,
  resolveOntologyParent,
} from '../TablePage/createTableFromSpec';
import { createFormField } from './useFormFieldPropertySync';
import {
  FIELD_TYPE_DEFAULT_OPTIONS,
  FORM_FIELD_TYPES,
  FORM_LAYOUT_TYPES,
  isChoiceFieldType,
  isLayoutType,
} from './fieldTypes';
import {
  classColumns,
  columnLabel,
  compatibleFieldTypes,
} from './tableColumns';

export const formSpecSchema = z.object({
  name: z.string().trim().min(1),
  parent: z
    .string()
    .optional()
    .describe(
      'Parent folder or drive. Defaults to the table, or current drive for a standalone form.',
    ),
  table: z
    .string()
    .optional()
    .describe(
      'Existing response table subject or #ref. Omit to create a standalone form with its own response table and schema.',
    ),
  rowName: z
    .string()
    .trim()
    .min(1)
    .optional()
    .describe(
      'Standalone response class name, e.g. Application. Defaults to Response.',
    ),
  description: z.string().optional(),
  pages: z
    .array(
      z.object({
        name: z.string().trim().min(1),
        fields: z.array(
          z.object({
            label: z.string().trim().min(1),
            type: z.enum([...FORM_FIELD_TYPES, ...FORM_LAYOUT_TYPES]),
            column: z
              .string()
              .optional()
              .describe(
                'For an existing table: column name, shortname, subject or #ref. Required for input fields. Never creates or changes shared columns.',
              ),
            required: z.boolean().optional(),
            choices: z
              .array(z.string().trim().min(1))
              .min(1)
              .optional()
              .describe(
                'Choice labels for standalone radio, dropdown, multi-select or picture-choice questions.',
              ),
            description: z.string().optional(),
            placeholder: z
              .string()
              .optional()
              .describe(
                'Input hint; prefer options.placeholder for new calls.',
              ),
            options: formFieldOptionsSchema.optional(),
          }),
        ),
      }),
    )
    .min(1),
});

export type FormSpec = z.infer<typeof formSpecSchema>;

/** Validate the whole spec before creating resources; link children as we go
 * so an interrupted request remains recoverable in the builder. */
export async function buildFormFromSpec(
  store: Store,
  input: FormSpec,
  opts: {
    driveSubject: string;
    addToOntology: (resource: Resource) => Promise<void>;
  },
) {
  const spec = formSpecSchema.parse(input);
  const ownsSchema = !spec.table;
  let table = spec.table ? await store.getResource(spec.table) : undefined;
  if (table && !table.hasClasses(dataBrowser.classes.table))
    throw new Error('Target resource is not a table');
  let dataClass = table
    ? await store.getResource(table.get(core.properties.classtype) as string)
    : undefined;
  const columns = dataClass
    ? await Promise.all(classColumns(dataClass).map(s => store.getResource(s)))
    : [];
  const mappings = new Map<
    FormSpec['pages'][number]['fields'][number],
    Resource
  >();
  const used = new Set<string>();

  for (const page of spec.pages) {
    for (const field of page.fields) {
      applyFormFieldOptions(field.type, undefined, field.options);
      if (
        isLayoutType(field.type) &&
        (field.options !== undefined || field.placeholder !== undefined)
      )
        throw new Error('Layout blocks cannot have input options');

      if (isLayoutType(field.type)) {
        if (field.column || field.choices || field.required)
          throw new Error(
            'Layout blocks cannot have columns, choices or required answers',
          );
        continue;
      }

      if (ownsSchema) {
        if (field.column)
          throw new Error('column is only supported with an existing table');
        if (isChoiceFieldType(field.type) !== !!field.choices)
          throw new Error(
            'Provide choices only for choice questions, and provide at least one choice',
          );
      } else {
        if (field.choices)
          throw new Error(
            'Existing table choices must be configured on the table',
          );
        const matches = columns.filter(
          p =>
            p.subject === field.column ||
            columnLabel(p) === field.column ||
            p.get(core.properties.shortname) === field.column,
        );
        if (matches.length !== 1)
          throw new Error(
            `Unknown or ambiguous column "${field.column}". Available: ${columns.map(columnLabel).join(', ')}`,
          );
        const property = matches[0];
        if (!compatibleFieldTypes(property).includes(field.type))
          throw new Error(
            `Incompatible field type for column "${field.column}"`,
          );
        if (used.has(property.subject))
          throw new Error(`Column "${field.column}" is used more than once`);
        used.add(property.subject);
        applyFormFieldOptions(
          field.type,
          undefined,
          field.options,
          property.get(dataBrowser.properties.max) as number | undefined,
        );
        mappings.set(field, property);
      }
    }
  }

  if (dataClass) {
    for (const required of dataClass.getSubjects(core.properties.requires)) {
      if (!used.has(required))
        throw new Error(`Include required table column ${required}`);
    }
  }

  const parent = spec.parent ?? spec.table ?? opts.driveSubject;

  if (!dataClass) {
    dataClass = await createRowClass(store, {
      parent: await resolveOntologyParent(store, opts.driveSubject),
      tableName: spec.name,
      rowName: spec.rowName ?? 'Response',
    });
    await opts.addToOntology(dataClass);
    table = await store.newResource({
      parent,
      isA: dataBrowser.classes.table,
      propVals: {
        [core.properties.name]: spec.name,
        [core.properties.classtype]: dataClass.subject,
      },
    });
    await table.save();
  }

  if (!table) throw new Error('Missing response table');
  const form = await store.newResource({
    parent,
    isA: forms.classes.form,
    propVals: {
      [core.properties.name]: spec.name,
      ...(spec.description === undefined
        ? {}
        : { [core.properties.description]: spec.description }),
      [forms.properties.formDataClass]: dataClass.subject,
      [forms.properties.formTargetTable]: table.subject,
      [forms.properties.formOwnsSchema]: ownsSchema,
      [forms.properties.formPages]: [],
    },
  });
  await form.save();

  if (ownsSchema) {
    await table.set(core.properties.parent, form.subject);
    await table.save();
  }

  const pages = [];

  for (const pageSpec of spec.pages) {
    const page = await store.newResource({
      parent: form.subject,
      isA: forms.classes.formPage,
      propVals: {
        [core.properties.name]: pageSpec.name,
        [forms.properties.formFields]: [],
      },
    });
    await page.save();
    await form.set(forms.properties.formPages, [
      ...form.getSubjects(forms.properties.formPages),
      page.subject,
    ]);
    await form.save();
    const fields = [];

    for (const fieldSpec of pageSpec.fields) {
      const field = await createFormField(store, dataClass, ownsSchema, page, {
        ...fieldSpec,
        existingProperty: mappings.get(fieldSpec),
      });

      if (!isLayoutType(fieldSpec.type)) {
        await field.set(forms.properties.formFieldType, fieldSpec.type);
        await field.set(
          forms.properties.required,
          !!fieldSpec.required ||
            dataClass
              .getSubjects(core.properties.requires)
              .includes(field.get(forms.properties.formMapsTo) as string),
        );
        await field.set(
          forms.properties.formFieldOptions,
          applyFormFieldOptions(
            fieldSpec.type,
            {
              ...(FIELD_TYPE_DEFAULT_OPTIONS[fieldSpec.type] as object),
              ...(field.get(forms.properties.formFieldOptions) as object),
              ...(fieldSpec.placeholder === undefined
                ? {}
                : { placeholder: fieldSpec.placeholder }),
            },
            fieldSpec.options,
          ),
        );
      }

      if (fieldSpec.description !== undefined)
        await field.set(core.properties.description, fieldSpec.description);
      // Mapped fields initially use the column label; presentation can differ.
      if (!isLayoutType(fieldSpec.type))
        await field.set(core.properties.name, fieldSpec.label);
      await field.save();
      fields.push({
        subject: field.subject,
        label: fieldSpec.label,
        property: field.get(forms.properties.formMapsTo),
      });
    }

    pages.push({ subject: page.subject, fields });
  }

  store.notifyResourceManuallyCreated(form);

  return {
    form: form.subject,
    table: table.subject,
    class: dataClass.subject,
    pages,
  };
}
