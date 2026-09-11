import { expect, it, vi } from 'vitest';
import { z } from 'zod';
import { forms, core, dataBrowser } from '@tomic/react';
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
    'properties.pages.items.properties.fields.items.properties.options.properties.min',
  );
  expect(edit).toHaveProperty('properties.options.properties.max');
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
            options: { min: 10, max: 100, currency: 'USD' },
          },
        ],
      },
    ],
  });
  const result = await buildFormFromSpec(f.store, spec, f.opts);
  const field = f.resources.get(result.pages[0].fields[0].subject)!;
  expect(field.get(forms.properties.formFieldOptions)).toMatchObject({
    min: 10,
    max: 100,
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
  expect(description.pages[0].fields[0].availableOptions).toContain('min');
  await configureFormField(f.store, {
    form: result.form,
    page: 'Page',
    field: 'Budget',
    options: { max: 200, min: null },
  });
  expect(field.get(forms.properties.formFieldOptions)).toMatchObject({
    max: 200,
    currency: 'USD',
  });
  expect(field.get(forms.properties.formFieldOptions)).not.toHaveProperty(
    'min',
  );
});

it.each([
  ['short-text', { minLength: 3, maxLength: 30 }],
  ['multi-select', { minSelected: 1, maxSelected: 2 }],
  ['rating', { max: 10, icon: 'heart' }],
  ['likert', { scale: 7, minLabel: 'No', maxLabel: 'Yes' }],
  ['phone', { defaultCountry: 'NL', placeholder: 'Phone number' }],
  ['checkbox', { defaultValue: true }],
  ['choice-matrix', { rows: ['Quality'], columns: ['Poor', 'Good'] }],
  [
    'table-input',
    { columns: [{ label: 'Amount', type: 'number' }], minRows: 1, maxRows: 5 },
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
    { min: 20, max: 10 },
    { minLength: 5 },
    { min: 'five' },
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
            { label: 'Number', type: 'number', options: { min: 0, max: 10 } },
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
      options: { min: 20 },
    }),
  ).rejects.toThrow('min must not exceed max');
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
  await property.set(dataBrowser.properties.max, 2);
  await f.resources
    .get(result.form)!
    .set(forms.properties.formOwnsSchema, false);
  f.saved.length = 0;
  await expect(
    configureFormField(f.store, {
      form: result.form,
      page: 'Page',
      field: 'Pick',
      options: { maxSelected: 3 },
    }),
  ).rejects.toThrow('column limit');
  expect(f.saved).toEqual([]);
  expect(property.get(core.properties.allowsOnly)).toHaveLength(2);
});
