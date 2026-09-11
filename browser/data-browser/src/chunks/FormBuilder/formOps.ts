// @wc-ignore-file
import {
  core,
  dataBrowser,
  forms,
  type JSONValue,
  type Resource,
  type Store,
} from '@tomic/react';
import { z } from 'zod';
import {
  formFieldOptionsSchema,
  FORM_OPTION_KEYS,
  applyFormFieldOptions,
} from './formFieldOptionsSchema';
import { INFO_BOX_STYLES } from '@tomic/form-renderer';
import { createFormField } from './useFormFieldPropertySync';
import {
  classColumns,
  columnLabel,
  compatibleFieldTypes,
} from './tableColumns';
import { parseFieldOptions } from './FieldOptions/useFieldOptions';
import {
  FIELD_TYPE_DEFAULT_OPTIONS,
  FIELD_TYPE_TO_DATATYPE,
  FORM_FIELD_TYPES,
  FORM_LAYOUT_TYPES,
  isChoiceFieldType,
  isLayoutType,
  type AddableFieldType,
} from './fieldTypes';
import { stringToSlug } from '@helpers/stringToSlug';

const nameSchema = z.string().trim().min(1);
const patchSchema = z
  .record(z.string(), z.json())
  .describe(
    'Shallow patch: omitted keys stay unchanged; null removes a key. Resource references inside JSON must be full subjects.',
  );

export const configureFormSchema = z.object({
  form: z.string(),
  name: nameSchema.optional(),
  description: z.string().optional(),
  settings: patchSchema.optional(),
  styling: z
    .object({
      textColor: z.string().nullable().optional(),
      mainColor: z.string().nullable().optional(),
      backgroundColor: z.string().nullable().optional(),
      roundness: z.enum(['sharp', 'rounded', 'round']).nullable().optional(),
      fieldSpacing: z.enum(['small', 'large']).nullable().optional(),
      showProgressBar: z.boolean().nullable().optional(),
      saveDrafts: z.boolean().nullable().optional(),
      animatePageTransitions: z.boolean().nullable().optional(),
    })
    .optional(),
  customCss: z
    .string()
    .optional()
    .describe('Custom form CSS; empty string clears it.'),
  pageOrder: z
    .array(z.string())
    .optional()
    .describe('Every existing page exactly once, by subject or unique name.'),
});
export const configureFormPageSchema = z.object({
  form: z.string(),
  page: z
    .string()
    .optional()
    .describe(
      'Page subject or unique name. Omit to append a new page; name is then required.',
    ),
  name: nameSchema.optional(),
  description: z.string().optional(),
  fieldOrder: z
    .array(z.string())
    .optional()
    .describe(
      'Every field on this page exactly once, by subject or unique label.',
    ),
  remove: z
    .boolean()
    .optional()
    .describe(
      'Remove an empty page. Cannot remove the last page or combine with edits.',
    ),
});
export const configureFormFieldSchema = z.object({
  form: z.string(),
  page: z.string().describe('Containing page subject or unique name.'),
  field: z
    .string()
    .optional()
    .describe(
      'Field subject or unique label on this page. Omit to append a new field; label and type are then required.',
    ),
  label: nameSchema
    .optional()
    .describe(
      'Question label or heading; for paragraph/info-box, the body text.',
    ),
  type: z
    .enum([...FORM_FIELD_TYPES, ...FORM_LAYOUT_TYPES])
    .optional()
    .describe(
      'Existing fields can only switch to a compatible presentation; storage datatype and choice cardinality stay unchanged.',
    ),
  column: z
    .string()
    .optional()
    .describe(
      'New field only: an existing table column by name, shortname or subject. Required on forms using a shared schema.',
    ),
  required: z.boolean().optional(),
  description: z.string().optional(),
  options: formFieldOptionsSchema.optional(),
  choices: z
    .array(
      z.object({
        subject: z
          .string()
          .optional()
          .describe(
            'Existing Tag subject to keep or rename. Omit for a new option.',
          ),
        label: nameSchema,
      }),
    )
    .min(1)
    .optional()
    .describe(
      'Complete ordered choices for a form-owned choice question. Existing Tag subjects retain answer identity when renamed. Removed Tags and past answers are preserved. Shared table choices cannot be edited here.',
    ),
  infoBoxStyle: z.enum(INFO_BOX_STYLES).optional(),
  remove: z
    .boolean()
    .optional()
    .describe(
      'Delete the question/layout block while preserving its Property, Tags and responses. Cannot combine with edits.',
    ),
});

type Graph = Awaited<ReturnType<typeof readForm>>;
type FieldConfig = z.infer<typeof configureFormFieldSchema>;

async function readForm(store: Store, subject: string) {
  const form = await store.getResource(subject);
  if (!form.hasClasses(forms.classes.form))
    throw new Error('Resource is not a form');
  const dataClass = await store.getResource(
    form.get(forms.properties.formDataClass) as string,
  );
  const pages = await Promise.all(
    form.getSubjects(forms.properties.formPages).map(async s => {
      const page = await store.getResource(s);
      if (!page.hasClasses(forms.classes.formPage))
        throw new Error('Invalid form page');

      return {
        page,
        fields: await Promise.all(
          page
            .getSubjects(forms.properties.formFields)
            .map(f => store.getResource(f)),
        ),
      };
    }),
  );

  return {
    form,
    dataClass,
    pages,
    ownsSchema: form.get(forms.properties.formOwnsSchema) === true,
  };
}

function fieldType(field: Resource): AddableFieldType {
  if (field.hasClasses(forms.classes.formHeading)) return 'heading';
  if (field.hasClasses(forms.classes.formParagraph)) return 'paragraph';
  if (field.hasClasses(forms.classes.formInfoBox)) return 'info-box';
  if (!field.hasClasses(forms.classes.formField))
    throw new Error('Resource is not a form field');

  return field.get(forms.properties.formFieldType) as AddableFieldType;
}

function fieldLabel(field: Resource): string {
  const type = fieldType(field);

  return (
    (field.get(
      type === 'paragraph' || type === 'info-box'
        ? core.properties.description
        : core.properties.name,
    ) as string) ?? ''
  );
}

function resolve(
  resources: Resource[],
  reference: string,
  label = (r: Resource) => r.get(core.properties.name),
) {
  const exact = resources.find(r => r.subject === reference);
  if (exact) return exact;
  const matches = resources.filter(r => label(r) === reference);
  if (matches.length !== 1)
    throw new Error(
      `Unknown or ambiguous reference "${reference}". Use a subject from describe_form.`,
    );

  return matches[0];
}

function ordered(
  resources: Resource[],
  refs: string[],
  label?: (r: Resource) => string,
) {
  const next = refs.map(ref => resolve(resources, ref, label));
  if (
    next.length !== resources.length ||
    new Set(next.map(r => r.subject)).size !== resources.length
  )
    throw new Error('Order must include every existing item exactly once');

  return next;
}

/** Conditions must only refer to earlier input fields, including after an
 * ordering change or removal. This also prevents dangling condition links. */
async function validateOrder(store: Store, pages: Graph['pages']) {
  const earlier = new Set<string>();

  const check = async (resource: Resource) => {
    for (const s of resource.getSubjects(forms.properties.formConditions)) {
      const condition = await store.getResource(s);
      if (
        !earlier.has(
          condition.get(forms.properties.formConditionField) as string,
        )
      )
        throw new Error(
          'This change would break a condition: its question must remain earlier in the form',
        );
    }
  };

  for (const { page, fields } of pages) {
    await check(page);

    for (const field of fields) {
      await check(field);
      if (!isLayoutType(fieldType(field))) earlier.add(field.subject);
    }
  }
}

function merge(raw: JSONValue | undefined, changes: Record<string, unknown>) {
  const result = { ...parseFieldOptions(raw) };

  for (const [key, value] of Object.entries(changes)) {
    if (value === null) delete result[key];
    else if (value !== undefined) result[key] = value as JSONValue;
  }

  return result;
}

async function patch(
  resource: Resource,
  property: string,
  values?: Record<string, unknown>,
) {
  if (values !== undefined)
    await resource.set(property, merge(resource.get(property), values));
}

async function conditions(store: Store, resource: Resource) {
  return Promise.all(
    resource.getSubjects(forms.properties.formConditions).map(async subject => {
      const c = await store.getResource(subject);

      return {
        subject,
        field: c.get(forms.properties.formConditionField),
        operator: c.get(forms.properties.formConditionOperator),
        value: c.get(forms.properties.formConditionValue),
      };
    }),
  );
}

export async function describeForm(store: Store, subject: string) {
  const graph = await readForm(store, subject);
  const { form, dataClass } = graph;
  const columns = await Promise.all(
    classColumns(dataClass).map(async s => {
      const p = await store.getResource(s);

      return {
        subject: s,
        name: columnLabel(p),
        shortname: p.get(core.properties.shortname),
        datatype: p.get(core.properties.datatype),
        required: dataClass.getSubjects(core.properties.requires).includes(s),
        compatibleTypes: compatibleFieldTypes(p),
      };
    }),
  );
  const pages = await Promise.all(
    graph.pages.map(async ({ page, fields }) => ({
      subject: page.subject,
      name: page.get(core.properties.name),
      description: page.get(core.properties.description),
      conditions: await conditions(store, page),
      fields: await Promise.all(
        fields.map(async field => {
          const propertySubject = field.get(forms.properties.formMapsTo) as
            | string
            | undefined;
          const property = propertySubject
            ? await store.getResource(propertySubject)
            : undefined;
          const choices = property
            ? await Promise.all(
                property
                  .getSubjects(core.properties.allowsOnly)
                  .map(async s => {
                    const tag = await store.getResource(s);

                    return { subject: s, label: columnLabel(tag) };
                  }),
              )
            : [];

          return {
            subject: field.subject,
            label: fieldLabel(field),
            type: fieldType(field),
            availableOptions: FORM_OPTION_KEYS[fieldType(field)],
            description: field.get(core.properties.description),
            property: propertySubject,
            required:
              !!field.get(forms.properties.required) ||
              (!!propertySubject &&
                dataClass
                  .getSubjects(core.properties.requires)
                  .includes(propertySubject)),
            options: parseFieldOptions(
              field.get(forms.properties.formFieldOptions),
            ),
            choices,
            infoBoxStyle: field.get(forms.properties.formInfoBoxStyle),
            conditions: await conditions(store, field),
          };
        }),
      ),
    })),
  );

  return {
    form: form.subject,
    name: form.get(core.properties.name),
    description: form.get(core.properties.description),
    table: form.get(forms.properties.formTargetTable),
    class: dataClass.subject,
    ownsSchema: graph.ownsSchema,
    publishedAt: form.get(forms.properties.formPublishedAt),
    settings: parseFieldOptions(form.get(forms.properties.formSettings)),
    styling: parseFieldOptions(form.get(forms.properties.formStyling)),
    customCss: form.get(forms.properties.formCustomCss),
    columns,
    pages,
  };
}

export async function configureForm(
  store: Store,
  input: z.infer<typeof configureFormSchema>,
) {
  const config = configureFormSchema.parse(input);
  const graph = await readForm(store, config.form);
  const { form } = graph;
  const pages = config.pageOrder
    ? ordered(
        graph.pages.map(p => p.page),
        config.pageOrder,
      )
    : undefined;
  if (pages)
    await validateOrder(
      store,
      pages.map(page => graph.pages.find(p => p.page === page)!),
    );
  if (config.name !== undefined)
    await form.set(core.properties.name, config.name);
  if (config.description !== undefined)
    await form.set(core.properties.description, config.description);
  if (config.customCss !== undefined)
    await form.set(forms.properties.formCustomCss, config.customCss);
  await patch(form, forms.properties.formSettings, config.settings);
  await patch(form, forms.properties.formStyling, config.styling);
  if (pages)
    await form.set(
      forms.properties.formPages,
      pages.map(p => p.subject),
    );
  await form.save();

  return { form: form.subject };
}

export async function configureFormPage(
  store: Store,
  input: z.infer<typeof configureFormPageSchema>,
) {
  const config = configureFormPageSchema.parse(input);
  const graph = await readForm(store, config.form);

  if (!config.page) {
    if (!config.name || config.remove || config.fieldOrder)
      throw new Error(
        'A new page requires name and cannot include remove or fieldOrder',
      );
    const page = await store.newResource({
      parent: graph.form.subject,
      isA: forms.classes.formPage,
      propVals: {
        [core.properties.name]: config.name,
        [forms.properties.formFields]: [],
        ...(config.description === undefined
          ? {}
          : { [core.properties.description]: config.description }),
      },
    });
    await page.save();
    await graph.form.set(forms.properties.formPages, [
      ...graph.form.getSubjects(forms.properties.formPages),
      page.subject,
    ]);
    await graph.form.save();

    return { page: page.subject };
  }

  const page = resolve(
    graph.pages.map(p => p.page),
    config.page,
  );
  const entry = graph.pages.find(p => p.page === page)!;

  if (config.remove) {
    if (
      config.name !== undefined ||
      config.description !== undefined ||
      config.fieldOrder
    )
      throw new Error('Cannot combine removal with edits');
    if (graph.pages.length === 1 || entry.fields.length)
      throw new Error(
        'Only an empty page can be removed, and the last page must remain',
      );
    await graph.form.set(
      forms.properties.formPages,
      graph.pages.filter(p => p !== entry).map(p => p.page.subject),
    );
    await graph.form.save();
    await destroyPresentation(store, page);

    return { removed: page.subject };
  }

  const fields = config.fieldOrder
    ? ordered(entry.fields, config.fieldOrder, fieldLabel)
    : undefined;
  if (fields)
    await validateOrder(
      store,
      graph.pages.map(p => (p === entry ? { page, fields } : p)),
    );
  if (config.name !== undefined)
    await page.set(core.properties.name, config.name);
  if (config.description !== undefined)
    await page.set(core.properties.description, config.description);
  if (fields)
    await page.set(
      forms.properties.formFields,
      fields.map(f => f.subject),
    );
  await page.save();

  return { page: page.subject };
}

async function destroyPresentation(store: Store, resource: Resource) {
  for (const s of resource.getSubjects(forms.properties.formConditions))
    await (await store.getResource(s)).destroy();
  await resource.destroy();
}

export async function configureFormField(store: Store, input: FieldConfig) {
  const config = configureFormFieldSchema.parse(input);
  const graph = await readForm(store, config.form);
  const page = resolve(
    graph.pages.map(p => p.page),
    config.page,
  );
  const entry = graph.pages.find(p => p.page === page)!;
  let field = config.field
    ? resolve(entry.fields, config.field, fieldLabel)
    : undefined;

  if (config.remove) {
    if (
      !field ||
      Object.entries(config).some(
        ([key, value]) =>
          !['form', 'page', 'field', 'remove'].includes(key) &&
          value !== undefined,
      )
    )
      throw new Error(
        'Removal requires an existing field and cannot include edits',
      );
    if (
      graph.dataClass
        .getSubjects(core.properties.requires)
        .includes(field.get(forms.properties.formMapsTo) as string)
    )
      throw new Error('Cannot remove a required table column');
    await validateOrder(
      store,
      graph.pages.map(p =>
        p === entry ? { page, fields: p.fields.filter(f => f !== field) } : p,
      ),
    );
    await page.set(
      forms.properties.formFields,
      entry.fields.filter(f => f !== field).map(f => f.subject),
    );
    await page.save();
    await destroyPresentation(store, field);

    return { removed: field.subject };
  }

  const previousType = field ? fieldType(field) : undefined;
  const type = config.type ?? previousType;
  if (!type || (!field && !config.label))
    throw new Error('A new field requires label and type');
  if (field && config.column !== undefined)
    throw new Error(
      'An existing field cannot be remapped; add a new field instead',
    );
  if (
    previousType &&
    (isLayoutType(type) || isLayoutType(previousType)) &&
    type !== previousType
  )
    throw new Error('Cannot switch between layout block types or questions');
  if (
    isLayoutType(type) &&
    (config.column !== undefined ||
      config.required !== undefined ||
      config.options !== undefined ||
      config.choices !== undefined)
  )
    throw new Error(
      'Layout blocks cannot have question options, columns, choices or required answers',
    );
  if (config.infoBoxStyle !== undefined && type !== 'info-box')
    throw new Error('infoBoxStyle requires an info-box');
  let property = field?.get(forms.properties.formMapsTo)
    ? await store.getResource(field.get(forms.properties.formMapsTo) as string)
    : undefined;

  if (!field && config.column) {
    const columns = await Promise.all(
      classColumns(graph.dataClass).map(s => store.getResource(s)),
    );
    const reference = config.column;
    const matches = columns.filter(
      p =>
        p.subject === reference ||
        columnLabel(p) === reference ||
        p.get(core.properties.shortname) === reference,
    );
    if (matches.length !== 1)
      throw new Error(
        'Unknown or ambiguous column; use its subject from describe_form',
      );
    property = matches[0];
    if (
      graph.pages.some(p =>
        p.fields.some(
          f => f.get(forms.properties.formMapsTo) === property!.subject,
        ),
      )
    )
      throw new Error('This column already has a question');
  }

  if (!field && !isLayoutType(type) && !graph.ownsSchema && !property)
    throw new Error(
      'Select an existing table column; add new columns on the table first',
    );

  if (property && !isLayoutType(type)) {
    const allowed = compatibleFieldTypes(property);
    // Composite standalone fields have no table picker presentation yet.
    if (
      !allowed.includes(type) &&
      !(
        previousType === type &&
        property.get(core.properties.datatype) === FIELD_TYPE_TO_DATATYPE[type]
      )
    )
      throw new Error('Incompatible field type for the existing column');
    if (
      config.required === false &&
      graph.dataClass
        .getSubjects(core.properties.requires)
        .includes(property.subject)
    )
      throw new Error('Cannot make a required table column optional');
  }

  if (config.choices && (!graph.ownsSchema || !isChoiceFieldType(type)))
    throw new Error(
      'Choices can only be edited on form-owned choice questions',
    );
  if (!field && !property && isChoiceFieldType(type) && !config.choices)
    throw new Error('A new choice question requires choices');
  const existingTags = property?.getSubjects(core.properties.allowsOnly) ?? [];

  if (config.choices) {
    const subjects = config.choices.flatMap(c =>
      c.subject ? [c.subject] : [],
    );
    if (
      new Set(subjects).size !== subjects.length ||
      subjects.some(s => !existingTags.includes(s))
    )
      throw new Error('Choice subjects must be distinct Tags of this question');
    if (
      new Set(config.choices.map(c => c.label)).size !== config.choices.length
    )
      throw new Error('Choice labels must be unique');
    if (
      property &&
      parseFieldOptions(field?.get(forms.properties.formFieldOptions))
        .optionsSource
    )
      throw new Error(
        'This question borrows choices; configure its source in the builder',
      );
  }

  if (!isLayoutType(type))
    applyFormFieldOptions(
      type,
      field
        ? field.get(forms.properties.formFieldOptions)
        : FIELD_TYPE_DEFAULT_OPTIONS[type],
      config.options,
      property?.get(dataBrowser.properties.max) as number | undefined,
    );
  const editsExistingChoices = !!property;

  // All input and membership checks above precede writes.
  if (!field) {
    field = await createFormField(
      store,
      graph.dataClass,
      graph.ownsSchema,
      page,
      {
        type,
        label: config.label!,
        existingProperty: property,
        choices: config.choices?.map(c => c.label),
      },
    );
    property = field.get(forms.properties.formMapsTo)
      ? await store.getResource(
          field.get(forms.properties.formMapsTo) as string,
        )
      : undefined;
  }

  if (config.choices && property && editsExistingChoices) {
    const tags = [];

    for (const choice of config.choices) {
      const tag = choice.subject
        ? await store.getResource(choice.subject)
        : await store.newResource({
            parent: property.subject,
            isA: dataBrowser.classes.tag,
            propVals: {
              [core.properties.shortname]:
                stringToSlug(choice.label) || 'option',
              [core.properties.name]: choice.label,
            },
          });
      await tag.set(core.properties.name, choice.label);
      await tag.save();
      tags.push(tag.subject);
    }

    await property.set(core.properties.allowsOnly, tags);
    await property.save();
  }

  if (config.label !== undefined)
    await field.set(
      type === 'paragraph' || type === 'info-box'
        ? core.properties.description
        : core.properties.name,
      config.label,
    );
  if (config.description !== undefined)
    await field.set(core.properties.description, config.description);
  if (config.infoBoxStyle !== undefined)
    await field.set(forms.properties.formInfoBoxStyle, config.infoBoxStyle);

  if (!isLayoutType(type)) {
    if (config.type !== undefined)
      await field.set(forms.properties.formFieldType, type);
    if (config.required !== undefined)
      await field.set(forms.properties.required, config.required);
    if (previousType !== type)
      await field.set(forms.properties.formFieldOptions, {
        ...(FIELD_TYPE_DEFAULT_OPTIONS[type] as object),
        ...parseFieldOptions(field.get(forms.properties.formFieldOptions)),
      });
    // Null explicitly deletes keys, including defaults introduced on creation.
    if (config.options !== undefined)
      await field.set(
        forms.properties.formFieldOptions,
        applyFormFieldOptions(
          type,
          field.get(forms.properties.formFieldOptions),
          config.options,
        ),
      );
  }

  await field.save();

  return { field: field.subject, property: property?.subject };
}
