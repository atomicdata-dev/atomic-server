/**
 * Client-side mirror of `atomic_lib::forms::validate_submission` /
 * `coerce_value` (`lib/src/forms.rs`). Keeps the same rules and messages so
 * a visitor sees the same errors the server would return, without a round
 * trip. The server remains the source of truth — this only improves UX; it
 * is not a substitute for server-side validation.
 */
import {
  ADDRESS_FIELDS,
  ADDRESS_REQUIRED_FIELDS,
  type FieldBlock,
  type FieldOptions,
  type FormBlock,
  type FormDefinition,
  type FormErrors,
  type FormValues,
  type TableColumn,
} from './types.js';
import { computeVisibility, isEmptyValue } from './conditions.js';
import { isCountryCode } from './countries.js';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
/** Deliberately permissive: digits with the usual separators, optional
 * country prefix. Mirrored by `is_valid_phone` in server/src/forms.rs.
 * Only reached for values the phone input didn't produce (see below). */
const PHONE_RE = /^\+?[0-9(][0-9\s\-().]{4,24}$/;
/** E.164 — what `react-phone-number-input` hands back: a `+`, a country
 * calling code and 7 to 15 digits in total, no separators. Checked instead
 * of `PHONE_RE` so a half-typed number is caught before submitting.
 * Everything this accepts `is_valid_phone` accepts too. */
const E164_RE = /^\+[1-9]\d{6,14}$/;
/** `+` followed by digits and nothing else — the shape only the phone input
 * produces, so it's safe to hold to the stricter rule. A hand-written or
 * imported international number (`+31 6 1234 5678`) has separators and keeps
 * the loose one. */
const COMPACT_INTERNATIONAL_RE = /^\+\d+$/;
/** Mirrored by `is_valid_url` in server/src/forms.rs. */
const URL_RE = /^https?:\/\/[^\s/$.?#][^\s]*$/i;

/** Default number of points on a `likert` scale. */
export const DEFAULT_LIKERT_SCALE = 5;
/** Default number of `rating` steps. */
export const DEFAULT_RATING_MAX = 5;

export function likertScale(options: FieldOptions): number {
  const scale = Math.round(Number(options.scale));

  return Number.isFinite(scale) && scale >= 2 && scale <= 11
    ? scale
    : DEFAULT_LIKERT_SCALE;
}

export function ratingMax(options: FieldOptions): number {
  const max = Math.round(Number(options.max));

  return Number.isFinite(max) && max >= 2 && max <= 10
    ? max
    : DEFAULT_RATING_MAX;
}

/** How many options a multi-pick question accepts. A bound has to be a whole
 * number of at least one to mean anything, so everything else — a blank
 * input, `0`, junk from a hand-edited bag — reads as "no bound". Mirrors
 * `selection_bounds` in `server/src/forms.rs`. */
export function selectionBounds(options: FieldOptions): {
  min?: number;
  max?: number;
} {
  return {
    min: countBound(options.minSelected),
    max: countBound(options.maxSelected),
  };
}

function countBound(raw: unknown): number | undefined {
  const n = Math.round(Number(raw));

  return Number.isFinite(n) && n >= 1 ? n : undefined;
}

/** The line shown under a bounded multi-pick question, e.g. "Select up to
 * 3 options". `undefined` when the question is unbounded — most are. */
export function selectionHint(options: FieldOptions): string | undefined {
  const { min, max } = selectionBounds(options);

  if (min !== undefined && max !== undefined) {
    return min === max
      ? `Select exactly ${min} ${plural(min, 'option')}`
      : `Select between ${min} and ${max} options`;
  }

  if (min !== undefined) {
    return `Select at least ${min} ${plural(min, 'option')}`;
  }

  if (max !== undefined) {
    return `Select up to ${max} ${plural(max, 'option')}`;
  }

  return undefined;
}

function plural(n: number, word: string): string {
  return n === 1 ? word : `${word}s`;
}

/** `choice-matrix` shares `columns` with `table-input`, which stores objects
 * — normalize both to plain labels. */
export function matrixColumns(options: FieldOptions): string[] {
  return (options.columns ?? []).map(c =>
    typeof c === 'string' ? c : c.label,
  );
}

export function tableColumns(options: FieldOptions): TableColumn[] {
  return (options.columns ?? []).map(c =>
    typeof c === 'string' ? { label: c, type: 'text' as const } : c,
  );
}

function validateInStep(
  raw: unknown,
  max: number,
  what: string,
): string | null {
  const n = typeof raw === 'number' ? raw : Number(raw);

  if (!Number.isInteger(n)) return 'Expected a whole number';

  if (n < 1 || n > max) return `${what} must be between 1 and ${max}`;

  return null;
}

function validateBounds(n: number, options: FieldOptions): string | null {
  if (options.min !== undefined && n < options.min) {
    return `Must be at least ${options.min}`;
  }

  if (options.max !== undefined && n > options.max) {
    return `Must be at most ${options.max}`;
  }

  return null;
}

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
  return isEmptyValue(value);
}

/** Checks picked option subjects against the question's resolved options.
 * Mirrors `check_membership` in `server/src/forms.rs`, including its
 * fail-closed empty case: options come from `allowsOnly`, so "no options"
 * means there is nothing to pick, not that anything goes. */
function checkMembership(
  items: string[],
  options: FieldBlock['options'],
): string | null {
  const allowed = (options.options ?? []).map(option => option.value);

  for (const item of items) {
    if (!allowed.includes(item)) {
      return 'Not one of the allowed options';
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

    case 'multi-select':

    case 'dropdown-multi': {
      if (!Array.isArray(raw) || raw.some(v => typeof v !== 'string')) {
        return 'Expected an array of strings';
      }

      const membership = checkMembership(raw as string[], field.options);

      if (membership) return membership;

      const { min, max } = selectionBounds(field.options);

      if (min !== undefined && raw.length < min) {
        return `Please select at least ${min} option(s)`;
      }

      if (max !== undefined && raw.length > max) {
        return `At most ${max} option(s) allowed`;
      }

      return null;
    }

    case 'phone': {
      if (typeof raw !== 'string') return 'Expected a string';

      const phone = raw.trim();

      const ok = COMPACT_INTERNATIONAL_RE.test(phone)
        ? E164_RE.test(phone)
        : PHONE_RE.test(phone);

      return ok ? null : 'Not a valid phone number';
    }

    case 'country': {
      if (typeof raw !== 'string') return 'Expected a string';

      /* Stricter than `is_valid_country` on the server, which only checks the
       * shape: here the list of real countries is right there to check. */
      return isCountryCode(raw.trim()) ? null : 'Not a valid country';
    }

    case 'url': {
      if (typeof raw !== 'string') return 'Expected a string';

      return URL_RE.test(raw.trim())
        ? null
        : 'Not a valid URL (must start with http:// or https://)';
    }

    case 'currency': {
      const n = typeof raw === 'number' ? raw : Number(raw);

      if (Number.isNaN(n)) return 'Expected a number';

      return validateBounds(n, field.options);
    }

    case 'dropdown':
    case 'picture-choice':
      if (typeof raw !== 'string') return 'Expected a string';

      return checkMembership([raw], field.options);

    case 'likert':
      return validateInStep(raw, likertScale(field.options), 'Answer');

    case 'rating':
      return validateInStep(raw, ratingMax(field.options), 'Rating');

    case 'choice-matrix': {
      if (!isPlainObject(raw)) return 'Expected an object of row answers';

      const rows = field.options.rows ?? [];
      const columns = matrixColumns(field.options);

      for (const [row, answer] of Object.entries(raw)) {
        if (!rows.includes(row)) {
          return `'${row}' is not one of the rows`;
        }

        if (isEmpty(answer)) continue;

        if (typeof answer !== 'string' || !columns.includes(answer)) {
          return `'${String(answer)}' is not one of the allowed options`;
        }
      }

      if (field.required) {
        const missing = rows.find(row => isEmpty(raw[row]));

        if (missing !== undefined) {
          return 'Please answer every row';
        }
      }

      return null;
    }

    case 'table-input': {
      if (!Array.isArray(raw)) return 'Expected a list of rows';

      const columns = tableColumns(field.options);

      for (const row of raw) {
        if (!isPlainObject(row)) return 'Expected a list of rows';

        for (const [key, cell] of Object.entries(row)) {
          const column = columns.find(c => c.label === key);

          if (!column) return `'${key}' is not one of the columns`;

          if (isEmpty(cell)) continue;

          if (column.type === 'number') {
            if (typeof cell !== 'number' || Number.isNaN(cell)) {
              return `'${key}' must be a number`;
            }
          } else if (typeof cell !== 'string') {
            return `'${key}' must be text`;
          }
        }
      }

      const filled = raw.filter(row => !isEmpty(row)).length;

      if (
        field.options.minRows !== undefined &&
        filled < field.options.minRows
      ) {
        return `Please fill in at least ${field.options.minRows} row(s)`;
      }

      if (
        field.options.maxRows !== undefined &&
        filled > field.options.maxRows
      ) {
        return `At most ${field.options.maxRows} row(s) allowed`;
      }

      return null;
    }

    case 'address': {
      if (!isPlainObject(raw)) return 'Expected an address object';

      const known = ADDRESS_FIELDS.map(f => f.key as string);

      for (const [key, value] of Object.entries(raw)) {
        if (!known.includes(key)) return `'${key}' is not part of an address`;

        if (!isEmpty(value) && typeof value !== 'string') {
          return `'${key}' must be text`;
        }
      }

      if (field.required) {
        const missing = ADDRESS_REQUIRED_FIELDS.find(key => isEmpty(raw[key]));

        if (missing) {
          const label = ADDRESS_FIELDS.find(f => f.key === missing)?.label;

          return `${label ?? missing} is required`;
        }
      }

      return null;
    }

    default:
      return `Unknown field type: ${field.type as string}`;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export interface ValidationResult {
  errors: FormErrors;
  /** Values coerced into submit-ready shapes (e.g. datetime -> epoch ms). Only present for valid fields. */
  values: FormValues;
}

/** Validates every *visible* field on the given page (or every visible
 * field in the whole definition when `pageIndex` is omitted), including
 * requiredness. Hidden fields are skipped — required-on-hidden is not an
 * error, and their values are not copied into the coerced result. */
export function validatePage(
  definition: FormDefinition,
  pageIndex: number,
  values: FormValues,
): ValidationResult {
  const errors: FormErrors = {};
  const coerced: FormValues = {};
  const visibility = computeVisibility(definition, values);

  if (!visibility.pageIndices.includes(pageIndex)) {
    return { errors, values: coerced };
  }

  const blocks: FormBlock[] = definition.pages[pageIndex]?.blocks ?? [];
  const visibleBlocks = visibility.blocks[pageIndex] ?? new Set<number>();

  for (let i = 0; i < blocks.length; i++) {
    const block = blocks[i];

    if (block.kind !== 'field' || !visibleBlocks.has(i)) continue;

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
