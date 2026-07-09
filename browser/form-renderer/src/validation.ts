/**
 * Client-side mirror of `atomic_lib::forms::validate_submission` /
 * `coerce_value` (`lib/src/forms.rs`). Keeps the same rules and messages so
 * a visitor sees the same errors the server would return, without a round
 * trip. The server remains the source of truth — this only improves UX; it
 * is not a substitute for server-side validation.
 */
import type {
  FieldBlock,
  FormBlock,
  FormDefinition,
  FormErrors,
  FormValues,
} from './types.js';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function fieldBlocks(definition: FormDefinition): FieldBlock[] {
  const fields: FieldBlock[] = [];

  for (const page of definition.pages) {
    for (const block of page.blocks) {
      if (block.kind === 'field') {
        fields.push(block);
      }
    }
  }

  return fields;
}

function isEmpty(value: unknown): boolean {
  if (value === undefined || value === null) {
    return true;
  }

  if (typeof value === 'string') {
    return value.length === 0;
  }

  if (Array.isArray(value)) {
    return value.length === 0;
  }

  return false;
}

function checkMembership(
  items: string[],
  options: FieldBlock['options'],
): string | null {
  const allowed = options.options;

  if (!allowed) {
    return null;
  }

  for (const item of items) {
    if (!allowed.includes(item)) {
      return `'${item}' is not one of the allowed options`;
    }
  }

  return null;
}

/** Validates and coerces a single field's raw (pre-submit) value. Returns an
 * error message, or `null` if the value is valid. Does not check
 * requiredness on empty values — callers decide whether "not answered yet"
 * should show as an error (e.g. only after a submit attempt). */
export function validateFieldValue(
  field: FieldBlock,
  raw: unknown,
): string | null {
  if (isEmpty(raw)) {
    return null;
  }

  switch (field.type) {
    case 'short-text':
    case 'long-text':
      return typeof raw === 'string' ? null : 'Expected a string';

    case 'email': {
      if (typeof raw !== 'string') return 'Expected a string';

      return EMAIL_RE.test(raw) ? null : 'Not a valid email address';
    }

    case 'number': {
      const n = typeof raw === 'number' ? raw : Number(raw);

      if (Number.isNaN(n)) return 'Expected a number';

      if (field.options.min !== undefined && n < field.options.min) {
        return `Must be at least ${field.options.min}`;
      }

      if (field.options.max !== undefined && n > field.options.max) {
        return `Must be at most ${field.options.max}`;
      }

      return null;
    }

    case 'date':
      return typeof raw === 'string'
        ? null
        : 'Expected a date string (YYYY-MM-DD)';
    case 'datetime':
      return typeof raw === 'number'
        ? null
        : 'Expected a timestamp in ms since epoch';
    case 'checkbox':
      return typeof raw === 'boolean' ? null : 'Expected a boolean';
    case 'radio':
      if (typeof raw !== 'string') return 'Expected a string';

      return checkMembership([raw], field.options);

    case 'multi-select': {
      if (!Array.isArray(raw) || raw.some(v => typeof v !== 'string')) {
        return 'Expected an array of strings';
      }

      return checkMembership(raw as string[], field.options);
    }

    default:
      return `Unknown field type: ${field.type as string}`;
  }
}

export interface ValidationResult {
  errors: FormErrors;
  /** Values coerced into submit-ready shapes (e.g. datetime -> epoch ms). Only present for valid fields. */
  values: FormValues;
}

/** Validates every field on the given page (or every field in the whole
 * definition when `pageIndex` is omitted), including requiredness. */
export function validatePage(
  definition: FormDefinition,
  pageIndex: number,
  values: FormValues,
): ValidationResult {
  const errors: FormErrors = {};
  const coerced: FormValues = {};

  const blocks: FormBlock[] = definition.pages[pageIndex]?.blocks ?? [];

  for (const block of blocks) {
    if (block.kind !== 'field') continue;

    const raw = values[block.mapsTo];

    if (isEmpty(raw)) {
      if (block.required) {
        errors[block.mapsTo] = 'This field is required';
      }

      continue;
    }

    const error = validateFieldValue(block, raw);

    if (error) {
      errors[block.mapsTo] = error;
    } else {
      coerced[block.mapsTo] = raw;
    }
  }

  return { errors, values: coerced };
}

export function validateAll(
  definition: FormDefinition,
  values: FormValues,
): ValidationResult {
  const errors: FormErrors = {};
  const coerced: FormValues = {};

  for (let i = 0; i < definition.pages.length; i++) {
    const result = validatePage(definition, i, values);
    Object.assign(errors, result.errors);
    Object.assign(coerced, result.values);
  }

  return { errors, values: coerced };
}
