import {
  Datatype,
  type Expression,
  type JSONValue,
  type Property,
  type Resource,
} from '@tomic/react';
import { calendarDateToLocalDate } from '@helpers/dates/calendarDate';
import { stringToSlug } from '@helpers/stringToSlug';
import { evaluateFormula } from './formulaEngine';
import { formatClock } from './helpers/formatDuration';

/**
 * A column whose value is computed from the row rather than stored on it: a
 * duration, a days-since, an amount, "birthday within two weeks". Configuration,
 * not code — the View lists them in `view-derived-columns` and every view kind
 * renders them. See `planning/table-templates-and-mini-apps.md`.
 *
 * The value is a formula (evaluated by the Rust `evalexpr` crate, in the browser
 * and in the store alike) over `vars`, which bind the identifiers it uses to
 * property subjects: `coalesce(until, now()) - start`.
 */
export interface DerivedColumnSpec {
  /** Stable identity within the view — the grid column key. */
  id: string;
  /** Heading label. */
  label: string;
  formula: string;
  /** Identifier used in the formula → property subject. */
  vars: Record<string, string>;
  /** Column width in px. */
  width?: number;
  /** What the number means, for formatting. Defaults to a plain number. */
  valueKind?: DerivedValueKind;
}

/**
 * What kind of number a formula produces. Decides how a value and a total over
 * the column are formatted, which statistics are offered for it, and (for a
 * filter) what the value input asks for.
 */
export type DerivedValueKind =
  | 'duration'
  | 'days'
  | 'number'
  | 'date'
  | 'boolean';

export const DEFAULT_DERIVED_WIDTH = 120;

/** `3d ago` / `today` / `in 5d` — a days-since reads as a distance, not a count. */
function formatDays(days: number): string {
  if (days === 0) {
    return 'today';
  }

  return days > 0 ? `${days}d ago` : `in ${-days}d`;
}

const FORMATTERS: Record<DerivedValueKind, (value: number) => string> = {
  duration: formatClock,
  days: formatDays,
  // Amounts keep two decimals unless they're whole (`12` / `127.50`).
  number: value => (Number.isInteger(value) ? String(value) : value.toFixed(2)),
  date: instant => new Date(instant).toLocaleDateString(),
  boolean: value => (value ? '✓' : ''),
};

export function formatDerivedValue(
  spec: Pick<DerivedColumnSpec, 'valueKind'>,
  value: number,
): string {
  return FORMATTERS[spec.valueKind ?? 'number'](value);
}

/**
 * How to show a formula's result, guessed from its shape so a typed formula
 * needs no setting: a comparison is true or false, a span between two instants
 * is a duration, `days(..)` counts days, `addDays(..)` is a date.
 */
export function inferValueKind(
  formula: string,
  /** Whether every column the formula reads is a date or a datetime. */
  readsInstants: boolean,
): DerivedValueKind | undefined {
  const operand = String.raw`(?:coalesce\((?:[^()]|\(\))*\)|\w+|now\(\))`;

  if (/[<>]=?|[!=]=|&&|\|\|/.test(formula)) {
    return 'boolean';
  }

  if (
    readsInstants &&
    new RegExp(`^\\s*${operand}\\s*-\\s*${operand}\\s*$`).test(formula)
  ) {
    return 'duration';
  }

  return /^\s*days\(.*\)\s*$/.test(formula)
    ? 'days'
    : /^\s*addDays\(.*\)\s*$/.test(formula)
      ? 'date'
      : undefined;
}

/** The store's form of a column, so a total or a filter can be computed over it. */
export function toExpression(spec: DerivedColumnSpec): Expression | undefined {
  return spec.formula.trim() === ''
    ? undefined
    : { kind: 'formula', formula: spec.formula, vars: spec.vars };
}

/** Whether the formula reads the clock, so its value (and a query on it) moves. */
export function dependsOnNow(
  spec: Pick<DerivedColumnSpec, 'formula'>,
): boolean {
  return /\b(now|daysUntilAnniversary)\s*\(/.test(spec.formula);
}

/**
 * True while a cell's value ticks on its own every second: a running duration.
 * A days count changes once a day, so it does not subscribe to the ticker.
 */
export function isLive(spec: DerivedColumnSpec): boolean {
  return spec.valueKind === 'duration' && /\bnow\s*\(/.test(spec.formula);
}

/** The value for one row, from the current values of its properties. */
export function computeDerived(
  spec: DerivedColumnSpec,
  values: Record<string, JSONValue | undefined>,
  now: number,
): number | undefined {
  const expression = toExpression(spec);

  if (!expression) {
    return undefined;
  }

  return evaluateFormula(expression, values, now);
}

/** The property subjects a spec reads. */
export function specProperties(spec: DerivedColumnSpec): string[] {
  return [...new Set(Object.values(spec.vars))];
}

/** Pulls a spec's inputs off a row — for callers outside of render. */
export function rowValuesOf(
  row: Resource,
  spec: DerivedColumnSpec,
): Record<string, JSONValue | undefined> {
  return Object.fromEntries(
    specProperties(spec).map(property => [
      property,
      row.get(property) as JSONValue | undefined,
    ]),
  );
}

/**
 * Reads an instant: a TIMESTAMP is already a number of millis, a DATE is an ISO
 * day string — both place the row in time, so both are usable.
 */
export function readInstant(
  values: Record<string, JSONValue | undefined>,
  property: string,
): number | undefined {
  const value = values[property];

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

// --- Naming columns in a formula -------------------------------------------

/** A column's label as a formula identifier: lowercase a-z, 0-9 and `_`. */
export const columnSlug = (label: string): string =>
  label
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .replace(/^(\d)/, 'c$1') || 'column';

/**
 * Identifier → property subject for columns given as `[label, subject]`. Two
 * labels that slug alike get a numeric suffix (`price`, `price_2`); the same
 * column listed twice (say by name and by shortname) keeps one entry.
 */
export function columnSlugs(
  columns: Array<[label: string, subject: string]>,
): Record<string, string> {
  const slugs: Record<string, string> = {};

  for (const [label, subject] of columns) {
    const base = columnSlug(label);
    let slug = base;

    for (let n = 2; slugs[slug] !== undefined && slugs[slug] !== subject; n++) {
      slug = `${base}_${n}`;
    }

    slugs[slug] = subject;
  }

  return slugs;
}

/** Whether a property holds something a formula can read as a number. */
export function isFormulaProperty(property: Property): boolean {
  return [
    Datatype.INTEGER,
    Datatype.FLOAT,
    Datatype.TIMESTAMP,
    Datatype.DATE,
    Datatype.BOOLEAN,
  ].includes(property.datatype);
}

/** `evalexpr` names that are not columns: literals, and anything called. */
const NOT_COLUMNS = new Set(['true', 'false']);

/** The column identifiers a formula reads — not function names or literals. */
export function formulaIdentifiers(formula: string): string[] {
  const identifiers = formula
    .replace(/"[^"]*"/g, '')
    .matchAll(/(?<![\w:])[A-Za-z_]\w*(?!\s*\(|\w|::)/g);

  return [...new Set([...identifiers].map(m => m[0]))].filter(
    name => !NOT_COLUMNS.has(name),
  );
}

/**
 * Binds the identifiers a formula uses to property subjects. An identifier that
 * names no column comes back in `unknown`, with the closest column to suggest.
 */
export function bindFormula(
  formula: string,
  slugs: Record<string, string>,
): { vars: Record<string, string>; unknown: Array<[string, string?]> } {
  const vars: Record<string, string> = {};
  const unknown: Array<[string, string?]> = [];

  for (const name of formulaIdentifiers(formula)) {
    if (slugs[name]) {
      vars[name] = slugs[name];
    } else {
      unknown.push([name, closest(name, Object.keys(slugs))]);
    }
  }

  return { vars, unknown };
}

function closest(name: string, candidates: string[]): string | undefined {
  const distance = (a: string, b: string): number => {
    let row = Array.from({ length: b.length + 1 }, (_, i) => i);

    for (let i = 1; i <= a.length; i++) {
      const next = [i];

      for (let j = 1; j <= b.length; j++) {
        next[j] = Math.min(
          row[j] + 1,
          next[j - 1] + 1,
          row[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
        );
      }

      row = next;
    }

    return row[b.length];
  };

  const [best] = candidates.sort(
    (x, y) => distance(name, x) - distance(name, y),
  );

  return best && distance(name, best) <= Math.max(2, name.length / 2)
    ? best
    : undefined;
}

/** Builds a spec from a name and a formula that names columns by slug. */
export function specFromFormula(
  label: string,
  formula: string,
  slugs: Record<string, string>,
  rest: Partial<Pick<DerivedColumnSpec, 'id' | 'valueKind' | 'width'>> = {},
): DerivedColumnSpec {
  return {
    id: rest.id ?? stringToSlug(label),
    label,
    formula,
    vars: bindFormula(formula, slugs).vars,
    ...(rest.valueKind ? { valueKind: rest.valueKind } : {}),
    ...(rest.width ? { width: rest.width } : {}),
  };
}

// --- Reading what is stored -------------------------------------------------

type LegacyArgs = Record<string, string | number | undefined>;

/** The five fixed generators this replaced: their arguments and the formula each meant. */
const LEGACY: Record<
  string,
  [
    args: string[],
    formula: (v: string[]) => string,
    valueKind: DerivedValueKind,
  ]
> = {
  difference: [['from', 'to'], v => `${v[1]} - ${v[0]}`, 'duration'],
  elapsed: [
    ['from', 'until'],
    v => (v[1] ? `coalesce(${v[1]}, now()) - ${v[0]}` : `now() - ${v[0]}`),
    'duration',
  ],
  daysSince: [['from'], v => `days(now() - ${v[0]})`, 'days'],
  product: [['a', 'b'], v => `${v[0]} * ${v[1]}`, 'number'],
  offset: [['from', 'days'], v => `${v[0]} + ${v[1]} * 86400000.0`, 'date'],
};

/** A spec stored as `{ kind, args }`, as the same formula the store converts it to. */
function fromLegacy(kind: string, args: LegacyArgs) {
  const [names, formula, valueKind] = LEGACY[kind] ?? [];
  const vars: Record<string, string> = {};
  const operands = names?.map(name => {
    const arg = args[name];

    if (typeof arg === 'number') {
      return `(${Number.isInteger(arg) ? arg.toFixed(1) : arg})`;
    }

    if (typeof arg === 'string' && arg) {
      vars[`v${Object.keys(vars).length}`] = arg;

      return `v${Object.keys(vars).length - 1}`;
    }
  });

  // Only a running duration may leave an argument (the end) empty.
  if (!operands?.slice(0, kind === 'elapsed' ? 1 : undefined).every(Boolean)) {
    return undefined;
  }

  return { formula: formula(operands as string[]), vars, valueKind };
}

function readSpec(value: unknown): DerivedColumnSpec | undefined {
  if (typeof value !== 'object' || value === null) {
    return undefined;
  }

  const spec = value as Record<string, unknown>;

  if (typeof spec.id !== 'string' || typeof spec.label !== 'string') {
    return undefined;
  }

  const base = {
    id: spec.id,
    label: spec.label,
    ...(typeof spec.width === 'number' ? { width: spec.width } : {}),
  };

  if (typeof spec.formula === 'string') {
    const vars = spec.vars ?? {};
    const isVars =
      typeof vars === 'object' &&
      vars !== null &&
      Object.values(vars).every(v => typeof v === 'string');

    return isVars
      ? {
          ...base,
          formula: spec.formula,
          vars: vars as Record<string, string>,
          ...(typeof spec.valueKind === 'string'
            ? { valueKind: spec.valueKind as DerivedValueKind }
            : {}),
        }
      : undefined;
  }

  const args = spec.args as LegacyArgs | undefined;

  return typeof spec.kind === 'string' && typeof args === 'object' && args
    ? ({ ...base, ...fromLegacy(spec.kind, args) } as DerivedColumnSpec)
    : undefined;
}

/**
 * Reads the specs stored on a View, converting the older `{ kind, args }` form
 * to formulas. Anything malformed is dropped rather than thrown: hand-edited (or
 * assistant-written) config must not be able to take the whole table down with
 * it.
 */
export function parseDerivedColumnSpecs(
  value: JSONValue | undefined,
): DerivedColumnSpec[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return (value as unknown[]).flatMap(item => {
    const spec = readSpec(item);

    return spec?.formula ? [spec] : [];
  });
}
