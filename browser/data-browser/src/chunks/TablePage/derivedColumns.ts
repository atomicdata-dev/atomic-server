import {
  Datatype,
  type Expression,
  type JSONValue,
  type Property,
  type Resource,
} from '@tomic/react';
import { calendarDateToLocalDate } from '@helpers/dates/calendarDate';
import { formatClock } from './helpers/formatDuration';

/**
 * A column whose value is computed from the row rather than stored on it: a
 * duration, a days-since, an amount. Configuration, not code — the View lists
 * them in `view-derived-columns` and every view kind renders them, so a
 * mini-app that needs one is a template, not a renderer. See
 * `planning/table-templates-and-mini-apps.md`.
 *
 * Deliberately a fixed set of generators rather than a formula language: these
 * five cover every mini-app on that list, and a formula language can wait until
 * one of them doesn't.
 */
export type DerivedColumnKind =
  | 'difference'
  | 'elapsed'
  | 'daysSince'
  | 'product'
  | 'offset';

/** Either a property subject to read off the row, or a literal number. */
export type DerivedColumnArg = string | number;

export interface DerivedColumnSpec {
  /** Stable identity within the view — the grid column key. */
  id: string;
  /** Heading label. */
  label: string;
  kind: DerivedColumnKind;
  /** The generator's arguments, by the names it declares. */
  args: Record<string, DerivedColumnArg>;
  /** Column width in px. Falls back to the generator's default. */
  width?: number;
}

/**
 * One argument of a generator, described richly enough for the column dialog to
 * build its own form — which properties may fill it, whether a number can be
 * typed instead, whether it may be left empty.
 */
export interface DerivedColumnArgSpec {
  /** Field label in the column dialog. */
  label: string;
  /** Which of the class's properties can fill this argument. */
  accepts: 'instant' | 'number';
  /** True when a fixed number may be typed in instead of picking a property. */
  allowsLiteral?: boolean;
  /** True when the column still computes with this argument left empty. */
  optional?: boolean;
}

/**
 * What kind of number a generator produces. Decides how a total over the column
 * is formatted, which statistics are offered for it, and (for a filter) what the
 * value input asks for.
 */
export type DerivedValueKind = 'duration' | 'days' | 'number' | 'date';

interface DerivedColumnGenerator {
  /** Name of this generator in the "add computed column" picker. */
  title: string;
  /** What its value is, beyond "a number". */
  valueKind: DerivedValueKind;
  /** One line saying what it computes, shown under the picker. */
  description: string;
  /** Prefills the column name. */
  defaultLabel: string;
  /** The arguments this generator reads. */
  args: Record<string, DerivedColumnArgSpec>;
  /** Default column width in px. */
  width: number;
  /**
   * The value to show, or undefined for an empty cell. `now` is only read by
   * generators that measure against the present.
   *
   * A pure function of the resolved argument values — see {@link ArgValues} for
   * why it does not take the row.
   */
  compute: (
    values: ArgValues,
    args: Record<string, DerivedColumnArg>,
    now: number,
  ) => number | undefined;
  format: (value: number) => string;
  /**
   * True while this row's value keeps changing on its own, so its cell
   * subscribes to the 1s ticker (and is emphasised as live).
   */
  live?: (values: ArgValues, args: Record<string, DerivedColumnArg>) => boolean;
}

const DAY_MS = 86_400_000;

/**
 * The values of the properties a spec's arguments name, by property subject.
 *
 * Generators are functions of *this* rather than of the row, so that a cell can
 * subscribe to exactly these values and recompute when one changes. Passing the
 * `Resource` instead looks simpler and is the bug it used to have: the React
 * Compiler memoizes a render-time read on the resource proxy's identity, and the
 * store mutates resources in place, so that identity never changes and the value
 * is computed once and cached forever.
 */
export type ArgValues = Record<string, JSONValue | undefined>;

/** Every generator's argument list, so a cell knows how many to subscribe to. */
export const MAX_DERIVED_ARGS = 2;

/** The property subjects a spec reads, in declaration order. */
export function argProperties(spec: DerivedColumnSpec): string[] {
  return Object.values(spec.args).filter(
    (arg): arg is string => typeof arg === 'string' && arg !== '',
  );
}

/** Pulls the argument's values off a row — for callers outside of render. */
export function argValuesOf(row: Resource, spec: DerivedColumnSpec): ArgValues {
  return Object.fromEntries(
    argProperties(spec).map(property => [
      property,
      row.get(property) as JSONValue | undefined,
    ]),
  );
}

/**
 * Reads an instant: a TIMESTAMP is already a number of millis, a DATE is an ISO
 * day string — both place the row in time, so both are usable. A literal number
 * argument is the instant itself.
 */
export function readInstant(
  values: ArgValues,
  arg: DerivedColumnArg | undefined,
): number | undefined {
  if (typeof arg === 'number') {
    return arg;
  }

  if (typeof arg !== 'string' || arg === '') {
    return undefined;
  }

  const value = values[arg];

  if (typeof value === 'number') {
    return value;
  }

  if (typeof value === 'string') {
    // A civil date has no zone: read it as local midnight, like the local
    // date-and-time inputs, not as the UTC midnight `Date.parse` gives.
    const local = calendarDateToLocalDate(value);

    if (local) {
      return local.getTime();
    }

    const parsed = Date.parse(value);

    return Number.isNaN(parsed) ? undefined : parsed;
  }

  return undefined;
}

/** Reads a plain number: the literal itself, or the value for a property. */
function readNumber(
  values: ArgValues,
  arg: DerivedColumnArg | undefined,
): number | undefined {
  if (typeof arg === 'number') {
    return arg;
  }

  if (typeof arg !== 'string' || arg === '') {
    return undefined;
  }

  const value = values[arg];

  return typeof value === 'number' ? value : undefined;
}

/** `3d ago` / `today` / `in 5d` — a days-since reads as a distance, not a count. */
function formatDays(days: number): string {
  if (days === 0) {
    return 'today';
  }

  return days > 0 ? `${days}d ago` : `in ${-days}d`;
}

/** Amounts keep two decimals unless they're whole (`12` / `127.50`). */
function formatAmount(value: number): string {
  return Number.isInteger(value) ? String(value) : value.toFixed(2);
}

function formatDate(instant: number): string {
  return new Date(instant).toLocaleDateString();
}

export const DERIVED_COLUMN_GENERATORS: Record<
  DerivedColumnKind,
  DerivedColumnGenerator
> = {
  /** `to − from`: a finished duration, a lead time. */
  difference: {
    title: 'Time between two dates',
    description:
      'The span from one date or time column to another, as a clock.',
    defaultLabel: 'Duration',
    args: {
      from: { label: 'From', accepts: 'instant' },
      to: { label: 'To', accepts: 'instant' },
    },
    valueKind: 'duration',
    width: 130,
    compute: (values, args) => {
      const from = readInstant(values, args.from);
      const to = readInstant(values, args.to);

      return from === undefined || to === undefined ? undefined : to - from;
    },
    format: formatClock,
  },
  /**
   * `(until ?? now) − from`: the ticking variant. A row with a `from` but no
   * `until` is still running, which is exactly what a timer entry is.
   */
  elapsed: {
    title: 'Live duration',
    description:
      'Counts up from a start until an end is filled in — a row without an end is still running.',
    defaultLabel: 'Duration',
    args: {
      from: { label: 'Start', accepts: 'instant' },
      until: { label: 'End', accepts: 'instant', optional: true },
    },
    valueKind: 'duration',
    width: 130,
    compute: (values, args, now) => {
      const from = readInstant(values, args.from);

      if (from === undefined) {
        return undefined;
      }

      return (readInstant(values, args.until) ?? now) - from;
    },
    format: formatClock,
    live: (values, args) =>
      readInstant(values, args.from) !== undefined &&
      readInstant(values, args.until) === undefined,
  },
  /** Whole days between `from` and now — "days since last contact". */
  daysSince: {
    title: 'Days since',
    description: 'Whole days between a date column and today.',
    defaultLabel: 'Days since',
    args: { from: { label: 'Date', accepts: 'instant' } },
    valueKind: 'days',
    width: 110,
    compute: (values, args, now) => {
      const from = readInstant(values, args.from);

      return from === undefined ? undefined : Math.floor((now - from) / DAY_MS);
    },
    format: formatDays,
  },
  /** `a × b` — quantity × price, hours × rate. Either side may be a literal. */
  product: {
    title: 'Multiplication',
    description:
      'Two numbers multiplied — quantity × price, hours × rate. Either side can be a fixed number.',
    defaultLabel: 'Total',
    args: {
      a: { label: 'First value', accepts: 'number', allowsLiteral: true },
      b: { label: 'Second value', accepts: 'number', allowsLiteral: true },
    },
    valueKind: 'number',
    width: 110,
    compute: (values, args) => {
      const a = readNumber(values, args.a);
      const b = readNumber(values, args.b);

      return a === undefined || b === undefined ? undefined : a * b;
    },
    format: formatAmount,
  },
  /** `from + days` — a next-due date from a last-done date and an interval. */
  offset: {
    title: 'Date plus days',
    description:
      'A date shifted by a number of days — a next-due date from a last-done date and an interval.',
    defaultLabel: 'Next due',
    args: {
      from: { label: 'Date', accepts: 'instant' },
      days: { label: 'Days', accepts: 'number', allowsLiteral: true },
    },
    valueKind: 'date',
    width: 130,
    compute: (values, args) => {
      const from = readInstant(values, args.from);
      const days = readNumber(values, args.days);

      return from === undefined || days === undefined
        ? undefined
        : from + days * DAY_MS;
    },
    format: formatDate,
  },
};

/** The kinds, in the order the column dialog offers them. */
export const DERIVED_COLUMN_KINDS: DerivedColumnKind[] = [
  'elapsed',
  'difference',
  'daysSince',
  'product',
  'offset',
];

/** Whether a property can fill an argument that `accepts` this kind of value. */
export function propertyFitsArg(
  property: Property,
  accepts: DerivedColumnArgSpec['accepts'],
): boolean {
  if (accepts === 'instant') {
    return (
      property.datatype === Datatype.TIMESTAMP ||
      property.datatype === Datatype.DATE
    );
  }

  return (
    property.datatype === Datatype.INTEGER ||
    property.datatype === Datatype.FLOAT
  );
}

/**
 * The store's form of a computed column, so a total or a filter can be computed
 * over one where the rows live. The wire shape is the generator's own kind and
 * argument names, flattened — `{ kind: 'elapsed', from, until }`.
 *
 * Returns undefined for a spec that can't compute anything (an argument still
 * empty), because asking the store for it would only produce a blank.
 */
export function toExpression(spec: DerivedColumnSpec): Expression | undefined {
  if (!isDerivedColumnComplete(spec)) {
    return undefined;
  }

  return { kind: spec.kind, ...spec.args } as Expression;
}

/** True once every argument the generator requires is filled in. */
export function isDerivedColumnComplete(spec: DerivedColumnSpec): boolean {
  const generator = DERIVED_COLUMN_GENERATORS[spec.kind];

  if (!generator) {
    return false;
  }

  return Object.entries(generator.args).every(([name, arg]) => {
    if (arg.optional) {
      return true;
    }

    const value = spec.args[name];

    return (
      typeof value === 'number' || (typeof value === 'string' && value !== '')
    );
  });
}

function isSpec(value: unknown): value is DerivedColumnSpec {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const spec = value as Partial<DerivedColumnSpec>;

  return (
    typeof spec.id === 'string' &&
    typeof spec.label === 'string' &&
    typeof spec.kind === 'string' &&
    spec.kind in DERIVED_COLUMN_GENERATORS &&
    typeof spec.args === 'object' &&
    spec.args !== null &&
    Object.values(spec.args).every(
      arg => typeof arg === 'string' || typeof arg === 'number',
    )
  );
}

/**
 * Reads the specs stored on a View. Anything malformed is dropped rather than
 * thrown: hand-edited (or assistant-written) config must not be able to take
 * the whole table down with it.
 */
export function parseDerivedColumnSpecs(
  value: JSONValue | undefined,
): DerivedColumnSpec[] {
  if (!Array.isArray(value)) {
    return [];
  }

  // Through `unknown[]`: a spec is a narrower shape than `JSONValue`, which the
  // predicate overload of `filter` won't accept directly.
  return (value as unknown[]).filter(isSpec);
}
