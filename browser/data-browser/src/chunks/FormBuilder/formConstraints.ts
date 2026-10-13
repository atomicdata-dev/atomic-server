// @wc-ignore-file
import {
  getEffectiveConstraint,
  type Constraint,
  type JSONValue,
  type Store,
} from '@tomic/react';
import type { FieldOptionsBag } from './FieldOptions/useFieldOptions';

/**
 * How a form relates to the class constraints of its data class. A question's
 * limits are JSON Schema keywords. The class map is what every write has to
 * satisfy; the question's own options may only tighten it. The published
 * definition carries the narrowed result.
 *
 * Twin of `narrow_options` / `normalize_option_keys` in
 * `server/src/forms.rs`: change them together.
 * See `planning/class-constraints-and-forms.md`.
 */

type LimitKind = 'number' | 'text' | 'items';

const LIMIT_KEYS: Record<
  LimitKind,
  { lower: readonly string[]; upper: readonly string[] }
> = {
  number: {
    lower: ['minimum', 'exclusiveMinimum'],
    upper: ['maximum', 'exclusiveMaximum'],
  },
  text: { lower: ['minLength'], upper: ['maxLength'] },
  items: { lower: ['minItems'], upper: ['maxItems'] },
};

/** Which limits a question type takes, if any. */
function limitKind(type: string | undefined): LimitKind | undefined {
  switch (type) {
    case 'number':
    case 'currency':
      return 'number';
    case 'short-text':
    case 'long-text':
      return 'text';
    case 'multi-select':
    case 'dropdown-multi':
    case 'table-input':
      return 'items';
    default:
      return undefined;
  }
}

/** The names the limits were stored under before they became JSON Schema
 * keywords. `max` stays on `rating`: that is its number of steps. */
const LEGACY_KEYS: Record<string, [string, string][]> = {
  number: [
    ['min', 'minimum'],
    ['max', 'maximum'],
  ],
  currency: [
    ['min', 'minimum'],
    ['max', 'maximum'],
  ],
  'multi-select': [
    ['minSelected', 'minItems'],
    ['maxSelected', 'maxItems'],
  ],
  'dropdown-multi': [
    ['minSelected', 'minItems'],
    ['maxSelected', 'maxItems'],
  ],
  'table-input': [
    ['minRows', 'minItems'],
    ['maxRows', 'maxItems'],
  ],
};

/**
 * A question's options with the old limit names renamed to the JSON Schema
 * ones (`minSelected` -> `minItems`, `min` -> `minimum`, ...). A key under its
 * new name wins. Existing forms keep reading, and the first edit rewrites
 * them.
 */
export function normalizeFieldOptions(
  type: string | undefined,
  bag: FieldOptionsBag,
): FieldOptionsBag {
  const renames = type ? LEGACY_KEYS[type] : undefined;

  if (!renames || !renames.some(([old]) => old in bag)) {
    return bag;
  }

  const out = { ...bag };

  for (const [old, next] of renames) {
    if (old in out) {
      if (!(next in out)) out[next] = out[old];

      delete out[old];
    }
  }

  return out;
}

/** The constraint that applies to a form's mapped column: its data class's
 * map, with the Property's legacy fields as the fallback. */
export function columnConstraint(
  store: Pick<Store, 'getResourceLoading'>,
  dataClassSubject: string,
  propertySubject: string,
): Constraint {
  return getEffectiveConstraint(store, [dataClassSubject], propertySubject);
}

const isNumber = (v: unknown): v is number =>
  typeof v === 'number' && Number.isFinite(v);

/**
 * What the data class allows, laid under the question's own options: each
 * limit is the stricter of the two. Written back into the options under the
 * keyword names, which is what the definition (and so both validators) read.
 */
export function narrowFieldOptions(
  type: string | undefined,
  options: FieldOptionsBag,
  constraint: Constraint,
): FieldOptionsBag {
  const kind = limitKind(type);

  if (!kind) return options;

  const out = { ...options };
  const keys = LIMIT_KEYS[kind];

  for (const [list, pick] of [
    [keys.lower, Math.max],
    [keys.upper, Math.min],
  ] as const) {
    for (const key of list) {
      const fromClass = constraint[key as keyof Constraint];
      const own = out[key];

      if (!isNumber(fromClass)) continue;

      out[key] = isNumber(own) ? pick(own, fromClass) : fromClass;
    }
  }

  if (kind === 'text' && constraint.pattern) {
    out.pattern = constraint.pattern.source;
  }

  if (kind === 'items') {
    const { minItems, maxItems } = out;

    // A minimum above the maximum could never be met.
    if (isNumber(minItems) && isNumber(maxItems) && minItems > maxItems) {
      out.minItems = maxItems;
    }
  }

  return out;
}

/**
 * Throws when one of the question's own limits is looser than the data
 * class's: a question may only tighten what the class demands, since the
 * class is what every write has to satisfy.
 */
export function assertOptionsTighten(
  type: string | undefined,
  options: FieldOptionsBag,
  constraint: Constraint,
): void {
  const kind = limitKind(type);

  if (!kind) return;

  const { lower, upper } = LIMIT_KEYS[kind];

  for (const key of lower) {
    const own = options[key];
    const fromClass = constraint[key as keyof Constraint];

    if (isNumber(own) && isNumber(fromClass) && own < fromClass) {
      throw new Error(
        `${key} cannot be below the table column limit (${fromClass})`,
      );
    }
  }

  for (const key of upper) {
    const own = options[key];
    const fromClass = constraint[key as keyof Constraint];

    if (isNumber(own) && isNumber(fromClass) && own > fromClass) {
      throw new Error(
        `${key} cannot exceed the table column limit (${fromClass})`,
      );
    }
  }

  // A lower limit the class's upper limit rules out can never be met.
  for (const [lowerKey, upperKey] of [
    ['minimum', 'maximum'],
    ['minLength', 'maxLength'],
    ['minItems', 'maxItems'],
  ] as const) {
    const own = options[lowerKey];
    const ceiling = constraint[upperKey];

    if (
      lower.includes(lowerKey) &&
      isNumber(own) &&
      isNumber(ceiling) &&
      own > ceiling
    ) {
      throw new Error(
        `${lowerKey} cannot exceed the table column limit (${ceiling})`,
      );
    }
  }
}

/** The keywords of a constraint as JSON Schema keyword values. */
export function constraintKeywords(
  constraint: Constraint,
): Record<string, JSONValue> {
  const out: Record<string, JSONValue> = {};

  for (const [key, value] of Object.entries(constraint)) {
    if (value === undefined) continue;

    out[key] = value instanceof RegExp ? value.source : (value as JSONValue);
  }

  return out;
}

/**
 * What a submission to this question has to satisfy, as JSON Schema keywords:
 * the data class's constraint for the column, narrowed by the question's own
 * options. The schema `describe_form` returns is built from these.
 */
export function narrowedConstraintKeywords(
  type: string | undefined,
  options: FieldOptionsBag,
  constraint: Constraint,
): Record<string, JSONValue> {
  const out = constraintKeywords(constraint);
  const kind = limitKind(type);

  if (!kind) return out;

  const narrowed = narrowFieldOptions(
    type,
    normalizeFieldOptions(type, options),
    constraint,
  );

  for (const key of [...LIMIT_KEYS[kind].lower, ...LIMIT_KEYS[kind].upper]) {
    if (isNumber(narrowed[key])) out[key] = narrowed[key];
  }

  return out;
}
