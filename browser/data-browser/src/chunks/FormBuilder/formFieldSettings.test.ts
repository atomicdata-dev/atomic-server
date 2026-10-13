import { expect, it, vi } from 'vitest';
import { z } from 'zod';
import {
  forms,
  getEffectiveConstraint,
  setClassConstraint,
} from '@tomic/react';
import { optionSubjects } from '@helpers/withConstraint';
import { validateFieldValue, type FieldOptions } from '@tomic/form-renderer';
import { formSpecSchema, buildFormFromSpec } from './createFormFromSpec';
import {
  configureFormFieldSchema,
  configureFormField,
  describeForm,
} from './formOps';
import { formTestFixture } from './formTestFixture';

vi.mock('@components/Tag/tagColours', () => ({ tagColours: ['blue'] }));

it('advertises explicit numeric bounds in both creation and editing schemas', () => {
  const create = z.toJSONSchema(formSpecSchema);
  const edit = z.toJSONSchema(configureFormFieldSchema);
  expect(create).toHaveProperty(
    'properties.pages.items.properties.fields.items.properties.options.properties.minimum',
  );
  expect(edit).toHaveProperty('properties.options.properties.maximum');
});

it('creates, describes, patches and clears numeric bounds without losing other options', async () => {
  const f = formTestFixture();
  const spec = formSpecSchema.parse({
    name: 'Survey',
    pages: [
      {
        name: 'Page',
        fields: [
          {
            label: 'Budget',
            type: 'currency',
            options: { minimum: 10, maximum: 100, currency: 'USD' },
          },
        ],
      },
    ],
  });
  const result = await buildFormFromSpec(f.store, spec, f.opts);
  const field = f.resources.get(result.pages[0].fields[0].subject)!;
  expect(field.get(forms.properties.formFieldOptions)).toMatchObject({
    minimum: 10,
    maximum: 100,
    currency: 'USD',
  });
  const runtimeField = {
    kind: 'field' as const,
    type: 'currency' as const,
    label: 'Budget',
    mapsTo: 'budget',
    required: false,
    options: field.get(forms.properties.formFieldOptions) as FieldOptions,
  };
  expect(validateFieldValue(runtimeField, 9)).not.toBeNull();
  expect(validateFieldValue(runtimeField, 101)).not.toBeNull();
  expect(validateFieldValue(runtimeField, 50)).toBeNull();
  const description = await describeForm(f.store, result.form);
  expect(description.pages[0].fields[0].availableOptions).toContain('minimum');
  await configureFormField(f.store, {
    form: result.form,
    page: 'Page',
    field: 'Budget',
    options: { maximum: 200, minimum: null },
  });
  expect(field.get(forms.properties.formFieldOptions)).toMatchObject({
    maximum: 200,
    currency: 'USD',
  });
  expect(field.get(forms.properties.formFieldOptions)).not.toHaveProperty(
    'minimum',
  );
});

it.each([
  ['short-text', { minLength: 3, maxLength: 30 }],
  ['multi-select', { minItems: 1, maxItems: 2 }],
  ['rating', { max: 10, icon: 'heart' }],
  ['likert', { scale: 7, minLabel: 'No', maxLabel: 'Yes' }],
  ['phone', { defaultCountry: 'NL', placeholder: 'Phone number' }],
  ['checkbox', { defaultValue: true }],
  ['choice-matrix', { rows: ['Quality'], columns: ['Poor', 'Good'] }],
  [
    'table-input',
    {
      columns: [{ label: 'Amount', type: 'number' }],
      minItems: 1,
      maxItems: 5,
    },
  ],
])('persists %s settings on creation', async (type, options) => {
  const f = formTestFixture();
  const result = await buildFormFromSpec(
    f.store,
    formSpecSchema.parse({
      name: 'Survey',
      pages: [
        {
          name: 'Page',
          fields: [
            {
              label: 'Question',
              type,
              options,
              ...(type === 'multi-select' ? { choices: ['A', 'B'] } : {}),
            },
          ],
        },
      ],
    }),
    f.opts,
  );
  expect(
    f.resources
      .get(result.pages[0].fields[0].subject)!
      .get(forms.properties.formFieldOptions),
  ).toMatchObject(options);
});

it('rejects contradictory, inapplicable and malformed settings before creation', async () => {
  for (const options of [
    { minimum: 20, maximum: 10 },
    { minLength: 5 },
    { minimum: 'five' },
    { bogus: true },
  ]) {
    const f = formTestFixture();
    await expect(
      buildFormFromSpec(
        f.store,
        {
          name: 'Invalid',
          pages: [
            {
              name: 'Page',
              fields: [
                { label: 'Number', type: 'number', options: options as never },
              ],
            },
          ],
        },
        f.opts,
      ),
    ).rejects.toThrow();
    expect(f.saved).toEqual([]);
    expect(f.store.newResource).not.toHaveBeenCalled();
  }
});

it('checks a patch against retained bounds before editing any resource', async () => {
  const f = formTestFixture();
  const result = await buildFormFromSpec(
    f.store,
    formSpecSchema.parse({
      name: 'Survey',
      pages: [
        {
          name: 'Page',
          fields: [
            {
              label: 'Number',
              type: 'number',
              options: { minimum: 0, maximum: 10 },
            },
          ],
        },
      ],
    }),
    f.opts,
  );
  f.saved.length = 0;
  await expect(
    configureFormField(f.store, {
      form: result.form,
      page: 'Page',
      field: 'Number',
      label: 'Must not change',
      options: { minimum: 20 },
    }),
  ).rejects.toThrow('minimum must not exceed maximum');
  expect(f.saved).toEqual([]);
  expect(
    (await describeForm(f.store, result.form)).pages[0].fields[0].label,
  ).toBe('Number');
});

it('does not allow selection bounds to exceed a shared column limit', async () => {
  const f = formTestFixture();
  const result = await buildFormFromSpec(
    f.store,
    {
      name: 'Survey',
      pages: [
        {
          name: 'Page',
          fields: [
            { label: 'Pick', type: 'multi-select', choices: ['A', 'B'] },
          ],
        },
      ],
    },
    f.opts,
  );
  const field = f.resources.get(result.pages[0].fields[0].subject)!;
  const property = f.resources.get(
    field.get(forms.properties.formMapsTo) as string,
  )!;
  const dataClass = f.resources.get(
    f.resources.get(result.form)!.get(forms.properties.formDataClass) as string,
  )!;
  await setClassConstraint(dataClass, property.subject, { maxItems: 2 });
  await f.resources
    .get(result.form)!
    .set(forms.properties.formOwnsSchema, false);
  f.saved.length = 0;
  await expect(
    configureFormField(f.store, {
      form: result.form,
      page: 'Page',
      field: 'Pick',
      options: { maxItems: 3 },
    }),
  ).rejects.toThrow('column limit');
  expect(f.saved).toEqual([]);
  expect(
    optionSubjects(
      getEffectiveConstraint(f.store, [dataClass.subject], property.subject),
    ),
  ).toHaveLength(2);
});

/** Builds a one-question form and hands back what a test needs to poke at it. */
async function oneQuestion(
  question: Record<string, unknown>,
  constraint?: Record<string, unknown>,
) {
  const f = formTestFixture();
  const result = await buildFormFromSpec(
    f.store,
    formSpecSchema.parse({
      name: 'Survey',
      pages: [{ name: 'Page', fields: [{ label: 'Q', ...question }] }],
    }),
    f.opts,
  );
  const field = f.resources.get(result.pages[0].fields[0].subject)!;
  const property = f.resources.get(
    field.get(forms.properties.formMapsTo) as string,
  )!;
  const dataClass = f.resources.get(result.class)!;

  if (constraint) {
    await setClassConstraint(dataClass, property.subject, constraint);
  }

  return { f, result, field, property, dataClass };
}

it('reads the limit names forms stored before JSON Schema keywords', async () => {
  const { f, result, field } = await oneQuestion({ type: 'number' });
  await field.set(forms.properties.formFieldOptions, { min: 1, max: 5 });
  const options = (await describeForm(f.store, result.form)).pages[0].fields[0]
    .options;
  expect(options).toMatchObject({ minimum: 1, maximum: 5 });
  expect(options).not.toHaveProperty('min');
  // Editing rewrites the old names.
  await configureFormField(f.store, {
    form: result.form,
    page: 'Page',
    field: 'Q',
    options: { maximum: 4 },
  });
  expect(field.get(forms.properties.formFieldOptions)).toEqual({
    minimum: 1,
    maximum: 4,
  });
});

it('lets a question only tighten the limits of its table column', async () => {
  const { f, result } = await oneQuestion(
    { type: 'number' },
    { minimum: 0, maximum: 10 },
  );
  f.saved.length = 0;

  for (const [options, message] of [
    [{ maximum: 11 }, 'maximum cannot exceed the table column limit (10)'],
    [{ minimum: -1 }, 'minimum cannot be below the table column limit (0)'],
  ] as const) {
    await expect(
      configureFormField(f.store, {
        form: result.form,
        page: 'Page',
        field: 'Q',
        options,
      }),
    ).rejects.toThrow(message);
  }

  expect(f.saved).toEqual([]);
  await configureFormField(f.store, {
    form: result.form,
    page: 'Page',
    field: 'Q',
    options: { minimum: 2, maximum: 8 },
  });
});

it('describes the JSON Schema of a form: the class, narrowed by the question', async () => {
  const { f, result, field, property } = await oneQuestion(
    { type: 'number', required: true },
    { minimum: 0, maximum: 10 },
  );
  await field.set(forms.properties.formFieldOptions, {
    minimum: 2,
    maximum: 20,
  });
  const { schema } = await describeForm(f.store, result.form);
  const shortname = property.get(
    'https://atomicdata.dev/properties/shortname',
  ) as string;
  expect(schema).toMatchObject({
    type: 'object',
    required: [shortname],
    additionalProperties: false,
    properties: {
      [shortname]: { type: 'number', minimum: 2, maximum: 10 },
    },
  });
});

it('describes a choice question as an enum of its Tags', async () => {
  const { f, result, property } = await oneQuestion({
    type: 'multi-select',
    choices: ['A', 'B'],
  });
  const { schema } = await describeForm(f.store, result.form);
  const shortname = property.get(
    'https://atomicdata.dev/properties/shortname',
  ) as string;
  const items = (
    schema.properties as Record<string, { type: string; items: { enum: [] } }>
  )[shortname];
  expect(items.type).toBe('array');
  expect(items.items.enum).toHaveLength(2);
});
