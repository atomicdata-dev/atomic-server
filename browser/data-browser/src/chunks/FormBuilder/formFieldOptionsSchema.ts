// @wc-ignore-file
import { z } from 'zod';
import type { JSONValue } from '@tomic/react';
import type { AddableFieldType } from './fieldTypes';
import { parseFieldOptions } from './FieldOptions/useFieldOptions';

/** Mirrors the editable form-field-options keys in the builder. Resolved
 * choices, storage datatype and choice sources are managed separately. */
export const formFieldOptionsSchema = z
  .strictObject({
    placeholder: z
      .string()
      .nullable()
      .optional()
      .describe(
        'Input hint for text, email, phone, URL, country or number questions.',
      ),
    min: z
      .number()
      .nullable()
      .optional()
      .describe('Minimum allowed numeric answer (number/currency).'),
    max: z
      .number()
      .nullable()
      .optional()
      .describe(
        'Maximum numeric answer (number/currency), or rating steps (integer 3–10).',
      ),
    minLength: z
      .number()
      .int()
      .positive()
      .nullable()
      .optional()
      .describe('Minimum characters for short-text/long-text.'),
    maxLength: z
      .number()
      .int()
      .positive()
      .nullable()
      .optional()
      .describe('Maximum characters for short-text/long-text.'),
    minSelected: z
      .number()
      .int()
      .positive()
      .nullable()
      .optional()
      .describe('Minimum choices for multi-select/dropdown-multi.'),
    maxSelected: z
      .number()
      .int()
      .positive()
      .nullable()
      .optional()
      .describe(
        'Maximum choices for multi-select/dropdown-multi; cannot exceed the column limit.',
      ),
    currency: z
      .string()
      .regex(/^[A-Z]{3}$/)
      .nullable()
      .optional()
      .describe('Currency code, e.g. EUR or USD, for currency questions.'),
    defaultCountry: z
      .string()
      .regex(/^[A-Z]{2}$/)
      .nullable()
      .optional()
      .describe('Initial country code for phone/country, e.g. NL.'),
    defaultValue: z
      .boolean()
      .nullable()
      .optional()
      .describe('Initial checkbox state.'),
    scale: z
      .number()
      .int()
      .min(3)
      .max(11)
      .nullable()
      .optional()
      .describe('Likert scale points (3–11).'),
    minLabel: z
      .string()
      .nullable()
      .optional()
      .describe('Likert low-end label.'),
    maxLabel: z
      .string()
      .nullable()
      .optional()
      .describe('Likert high-end label.'),
    icon: z
      .enum(['star', 'heart'])
      .nullable()
      .optional()
      .describe('Rating icon.'),
    rows: z
      .array(z.string().trim().min(1))
      .min(1)
      .nullable()
      .optional()
      .describe('Statement labels for a choice-matrix.'),
    columns: z
      .union([
        z.array(z.string().trim().min(1)).min(1),
        z
          .array(
            z.strictObject({
              label: z.string().trim().min(1),
              type: z.enum(['text', 'number']).optional(),
            }),
          )
          .min(1),
      ])
      .nullable()
      .optional()
      .describe(
        'Choice-matrix: string labels. Table-input: objects with label and type (text/number).',
      ),
    minRows: z
      .number()
      .int()
      .nonnegative()
      .nullable()
      .optional()
      .describe('Minimum rows in a table-input answer.'),
    maxRows: z
      .number()
      .int()
      .positive()
      .nullable()
      .optional()
      .describe('Maximum rows in a table-input answer.'),
  })
  .describe(
    'Type-specific field options. Omitted keys stay unchanged; null clears a key. Numeric min/max differ from text minLength/maxLength, choice minSelected/maxSelected and table minRows/maxRows.',
  );

export type FormFieldOptionsPatch = z.infer<typeof formFieldOptionsSchema>;

const text = ['placeholder'] as const;
const numeric = ['min', 'max', 'placeholder'] as const;
const multiple = ['minSelected', 'maxSelected'] as const;

export const FORM_OPTION_KEYS: Record<
  AddableFieldType,
  readonly (keyof FormFieldOptionsPatch)[]
> = {
  'short-text': [...text, 'minLength', 'maxLength'],
  'long-text': [...text, 'minLength', 'maxLength'],
  email: text,
  url: text,
  phone: [...text, 'defaultCountry'],
  country: [...text, 'defaultCountry'],
  number: numeric,
  currency: [...numeric, 'currency'],
  checkbox: ['defaultValue'],
  rating: ['max', 'icon'],
  likert: ['scale', 'minLabel', 'maxLabel'],
  'multi-select': multiple,
  'dropdown-multi': multiple,
  'choice-matrix': ['rows', 'columns'],
  'table-input': ['columns', 'minRows', 'maxRows'],
  date: [],
  datetime: [],
  radio: [],
  dropdown: [],
  'picture-choice': [],
  address: [],
  heading: [],
  paragraph: [],
  'info-box': [],
};

/** Validate the resulting bounds, not just the patch: min: 20 must fail if
 * an existing max is 10. Does not modify the property or the original bag. */
export function applyFormFieldOptions(
  type: AddableFieldType,
  raw: JSONValue | undefined,
  input: FormFieldOptionsPatch = {},
  columnMax?: number,
): Record<string, JSONValue> {
  const patch = formFieldOptionsSchema.parse(input);
  const options = { ...parseFieldOptions(raw) };

  for (const [key, value] of Object.entries(patch)) {
    if (value === undefined) continue;

    if (value === null) {
      delete options[key];
      continue;
    }

    if (!FORM_OPTION_KEYS[type].includes(key as keyof FormFieldOptionsPatch))
      throw new Error(
        `Option "${key}" does not apply to ${type}. Available: ${FORM_OPTION_KEYS[type].join(', ') || '(none)'}`,
      );
    options[key] = value;
  }

  for (const [min, max] of [
    ['min', 'max'],
    ['minLength', 'maxLength'],
    ['minSelected', 'maxSelected'],
    ['minRows', 'maxRows'],
  ] as const) {
    if (
      FORM_OPTION_KEYS[type].includes(min) &&
      typeof options[min] === 'number' &&
      typeof options[max] === 'number' &&
      options[min] > options[max]
    )
      throw new Error(`${min} must not exceed ${max}`);
  }

  if (
    type === 'rating' &&
    options.max !== undefined &&
    (typeof options.max !== 'number' ||
      !Number.isInteger(options.max) ||
      options.max < 3 ||
      options.max > 10)
  )
    throw new Error('Rating max must be an integer from 3 to 10');
  if (
    type === 'choice-matrix' &&
    Array.isArray(options.columns) &&
    options.columns.some(c => typeof c !== 'string')
  )
    throw new Error('Choice-matrix columns must be strings');
  if (
    type === 'table-input' &&
    Array.isArray(options.columns) &&
    options.columns.some(c => typeof c !== 'object' || c === null)
  )
    throw new Error('Table-input columns must have a label and type');

  if (
    columnMax !== undefined &&
    (type === 'multi-select' || type === 'dropdown-multi')
  ) {
    for (const key of multiple)
      if (typeof options[key] === 'number' && options[key] > columnMax)
        throw new Error(
          `${key} cannot exceed the table column limit (${columnMax})`,
        );
  }

  return options;
}
