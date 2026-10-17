import {
  Datatype,
  type AggregateFunction,
  type AggregateGrouping,
  type AggregateGroup,
  type AggregateOutcome,
  type Aggregate,
  type Aggregation,
  type JSONValue,
  type Property,
} from '@tomic/react';
import {
  calendarDateToLocalDate,
  formatCalendarDate,
} from '@helpers/dates/calendarDate';
import {
  DERIVED_COLUMN_GENERATORS,
  toExpression,
  type ArgValues,
  type DerivedColumnArg,
  type DerivedColumnKind,
  type DerivedColumnSpec,
} from './derivedColumns';

/**
 * A statistic a view shows under its rows. Configuration on the View
 * (`view-aggregates`), computed by the store over **every** row the view
 * matches — filters included, paging excluded. So a "Sum of Amount" is the
 * answer for the whole table, not for the rows that happen to be loaded.
 * A quick filter narrows it to the rows that match (`aggregateRows`).
 */
export interface TableAggregate {
  /** Stable identity within the view. */
  id: string;
  /** The property whose values are aggregated. Absent for a plain row count. */
  property?: string;
  /**
   * The id of a computed column of this view, when the statistic is over a value
   * computed per row rather than stored on it — a duration, an amount. The store
   * evaluates the column's expression as it aggregates, so a sum of durations
   * covers every matching row like any other total.
   */
  derived?: string;
  function: AggregateFunction;
  /**
   * Which totals row this sits in, counting from 0. A column can carry one
   * statistic per row, so a table can show a sum and an average under the same
   * column. Absent means the first row.
   */
  row?: number;
}

/** How a date or timestamp breakdown column is bucketed. */
export type GroupGranularity = NonNullable<AggregateGrouping['granularity']>;

export const AGGREGATE_FUNCTIONS: AggregateFunction[] = [
  'sum',
  'avg',
  'min',
  'max',
  'count',
];

/** How each function reads in the UI: "Sum of Amount", "Rows". */
export const AGGREGATE_FUNCTION_LABELS: Record<AggregateFunction, string> = {
  sum: 'Sum',
  avg: 'Average',
  min: 'Minimum',
  max: 'Maximum',
  count: 'Count',
};

/** Properties worth summing or averaging. */
export function isNumericProperty(property: Property): boolean {
  return (
    property.datatype === Datatype.INTEGER ||
    property.datatype === Datatype.FLOAT
  );
}

/** Properties whose earliest/latest is meaningful. */
export function isInstantProperty(property: Property): boolean {
  return (
    property.datatype === Datatype.TIMESTAMP ||
    property.datatype === Datatype.DATE
  );
}

/** Which properties a function can be applied to. */
export function propertiesForFunction(
  properties: Property[],
  fn: AggregateFunction,
): Property[] {
  if (fn === 'sum' || fn === 'avg') {
    return properties.filter(isNumericProperty);
  }

  if (fn === 'min' || fn === 'max') {
    return properties.filter(p => isNumericProperty(p) || isInstantProperty(p));
  }

  // Counting works on anything: it counts the rows that have a value at all.
  return properties;
}

/**
 * Which statistics a computed column can carry. A date (a next-due) has no
 * meaningful sum or average; a duration or an amount has all of them.
 */
export function functionsForDerived(
  spec: DerivedColumnSpec,
): AggregateFunction[] {
  return DERIVED_COLUMN_GENERATORS[spec.kind].valueKind === 'date'
    ? ['min', 'max', 'count']
    : ['sum', 'avg', 'min', 'max', 'count'];
}

/**
 * Properties that make sense to break down by. A free-text column would give
 * one bucket per row, so only bounded or bucketable kinds are offered.
 */
export function isGroupableProperty(property: Property): boolean {
  return (
    property.datatype === Datatype.RESOURCEARRAY ||
    property.datatype === Datatype.ATOMIC_URL ||
    property.datatype === Datatype.BOOLEAN ||
    property.datatype === Datatype.SLUG ||
    isInstantProperty(property)
  );
}

/** Dates and timestamps are bucketed; everything else groups by exact value. */
export function granularityApplies(property: Property | undefined): boolean {
  return !!property && isInstantProperty(property);
}

/**
 * The default bucket for a breakdown column: a timestamp's exact values are
 * unique per row, so grouping by them is never what "per day" meant.
 */
export function defaultGranularity(
  property: Property | undefined,
): GroupGranularity {
  return granularityApplies(property) ? 'day' : 'exact';
}

function isAggregate(value: unknown): value is TableAggregate {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const spec = value as Partial<TableAggregate>;

  return (
    typeof spec.id === 'string' &&
    typeof spec.function === 'string' &&
    (AGGREGATE_FUNCTIONS as string[]).includes(spec.function) &&
    (spec.property === undefined || typeof spec.property === 'string') &&
    (spec.derived === undefined || typeof spec.derived === 'string') &&
    (spec.row === undefined ||
      (typeof spec.row === 'number' && Number.isInteger(spec.row)))
  );
}

/**
 * Reads the aggregates stored on a View. Anything malformed is dropped rather
 * than thrown — the same rule the derived columns follow: config can be written
 * by a person or the assistant, and a bad entry must not take the table down.
 */
export function parseAggregates(
  value: JSONValue | undefined,
): TableAggregate[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return (value as unknown[]).filter(isAggregate);
}

/**
 * Turns the view's config into the query's `aggregation`, or undefined when
 * there is nothing to compute (which keeps the query free of the extra pass).
 *
 * The timezone offset travels with it so day and month buckets are the user's
 * days, not UTC's — a 23:30 entry belongs to the day the user was living.
 */
/**
 * The id of the row count a breakdown asks for alongside the view's own
 * statistics. A group's `count` is how many rows contributed a value to THAT
 * statistic, so a sum of Estimate over tasks with no estimate reads 0: the
 * breakdown's "n rows" has to come from a count of every row instead.
 */
export const BREAKDOWN_ROWS_ID = '__breakdown_rows';

export function toAggregation(
  aggregates: TableAggregate[],
  groupByColumn: string | undefined,
  granularity: GroupGranularity,
  /** The view's computed columns, for the statistics that name one. */
  derivedColumns: DerivedColumnSpec[] = [],
): Aggregation | undefined {
  if (aggregates.length === 0) {
    return undefined;
  }

  const specById = new Map(derivedColumns.map(spec => [spec.id, spec]));

  const requests: Aggregate[] = aggregates.flatMap(
    ({ id, property, derived, function: fn }): Aggregate[] => {
      if (derived === undefined) {
        return [{ id, property, function: fn }];
      }

      const spec = specById.get(derived);
      const expression = spec && toExpression(spec);

      // The column it named is gone (or still incomplete). Asking anyway would
      // return an empty number and read as a broken total, so don't ask.
      return expression ? [{ id, expression, function: fn }] : [];
    },
  );

  if (requests.length === 0) {
    return undefined;
  }

  const live = aggregates.some(aggregate => {
    const spec = aggregate.derived
      ? specById.get(aggregate.derived)
      : undefined;

    return spec ? measuresAgainstNow(spec) : false;
  });

  return {
    // Rows are a display concern; each statistic is asked for once and carries
    // its own id, which is how the outcomes are matched back to it.
    aggregates: groupByColumn
      ? [...requests, { id: BREAKDOWN_ROWS_ID, function: 'count' }]
      : requests,
    group_by: groupByColumn
      ? {
          property: groupByColumn,
          granularity,
          tz_offset_minutes: -new Date().getTimezoneOffset(),
        }
      : undefined,
    // Only when something actually measures against the present, and quantized:
    // this value is part of the query's identity, so a raw `Date.now()` would
    // re-run the query on every render. A minute is close enough for a total
    // while the cells themselves tick every second.
    ...(live ? { now_ms: quantizedNow() } : {}),
  };
}

/** How coarsely `now` is passed to the store — see `toAggregation`. */
const NOW_QUANTUM_MS = 60_000;

function quantizedNow(): number {
  return Math.floor(Date.now() / NOW_QUANTUM_MS) * NOW_QUANTUM_MS;
}

/** Whether a computed column's value keeps moving on its own. */
function measuresAgainstNow(spec: DerivedColumnSpec): boolean {
  return spec.kind === 'daysSince' || spec.kind === 'elapsed';
}

/** How many totals rows the configuration needs (always at least one). */
export function aggregateRowCount(aggregates: TableAggregate[]): number {
  return aggregates.reduce(
    (rows, aggregate) => Math.max(rows, (aggregate.row ?? 0) + 1),
    1,
  );
}

/**
 * Matches a configured statistic to the outcome the store returned.
 *
 * By `id` when both sides carry one — two statistics over computed columns name
 * no property, so nothing else tells them apart. The `function:property` form is
 * the fallback for a store that predates the echoed id.
 */
export function aggregateKey(spec: {
  id?: string;
  property?: string;
  function: AggregateFunction;
}): string {
  return spec.id ? `id:${spec.id}` : `${spec.function}:${spec.property ?? ''}`;
}

/**
 * Formats a computed value for display, using the datatype of the property it
 * came from: the earliest of a date column is a date, a sum of amounts is a
 * number, and a count is always a plain integer.
 */
export function formatAggregateValue(
  value: number | null | undefined,
  fn: AggregateFunction,
  property: Property | undefined,
  /** The computed column the number came from, when it wasn't a property. */
  derived?: DerivedColumnSpec,
): string {
  // An answered count over no rows is zero: it is how an empty queue reads. The
  // store reports it as `null`, "no resource had a value", which for a count is
  // the same thing.
  if (fn === 'count' && value === null) {
    return '0';
  }

  if (value === null || value === undefined) {
    // Nothing to compute is not zero, and must not read as zero.
    return '—';
  }

  if (fn === 'count') {
    return value.toLocaleString();
  }

  // A sum of durations is a duration: format it the way the column itself does,
  // or "5:30:00" of logged time reads as 19800000.
  if (derived) {
    return DERIVED_COLUMN_GENERATORS[derived.kind].format(value);
  }

  if (
    (fn === 'min' || fn === 'max') &&
    property &&
    isInstantProperty(property)
  ) {
    const date = new Date(value);

    // A date column's extreme is UTC midnight of a civil date: read it back in
    // UTC, or it is the day before west of Greenwich.
    return property.datatype === Datatype.DATE
      ? date.toLocaleDateString(undefined, { timeZone: 'UTC' })
      : date.toLocaleString();
  }

  const rounded = value.toLocaleString(undefined, { maximumFractionDigits: 2 });

  // A nonzero total must not read as zero: 0.0000375 is a real measurement, and
  // two decimals would show it as "0". Keep three significant digits instead.
  if (value !== 0 && Number(value.toFixed(2)) === 0) {
    return value.toLocaleString(undefined, {
      maximumSignificantDigits: 3,
      maximumFractionDigits: 20,
    });
  }

  return rounded;
}

/** Formats a bucket key for display. Subjects are resolved by the caller. */
export function formatGroupKey(
  key: string,
  granularity: GroupGranularity,
): string {
  if (key === '') {
    return '(none)';
  }

  // Day and month keys are civil dates, already in the viewer's zone.
  if (granularity === 'day') {
    return calendarDateToLocalDate(key)
      ? formatCalendarDate(key, {
          weekday: 'short',
          day: 'numeric',
          month: 'short',
          year: 'numeric',
        })
      : key;
  }

  if (granularity === 'month') {
    return calendarDateToLocalDate(`${key}-01`)
      ? formatCalendarDate(`${key}-01`, {
          month: 'long',
          year: 'numeric',
        })
      : key;
  }

  return key;
}

/** Reads one property's value off a row. */
export type RowValueReader = (property: string) => JSONValue | undefined;

/** The store's default number of buckets per breakdown (`DEFAULT_GROUP_LIMIT`). */
const DEFAULT_GROUP_LIMIT = 100;

const ISO_DAY = /^(\d{4})-(\d{2})-(\d{2})/;

/** A stored value as a number, the way the store reads one (`value_as_number`). */
function valueAsNumber(value: JSONValue | undefined): number | undefined {
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : undefined;
  }

  if (typeof value === 'boolean') {
    return value ? 1 : 0;
  }

  if (typeof value !== 'string') {
    return undefined;
  }

  const trimmed = value.trim();

  // `Number('')` is 0; the store's parse fails on it, and so must this.
  if (trimmed !== '' && !Number.isNaN(Number(trimmed))) {
    return Number(trimmed);
  }

  // A DATE is UTC midnight of its day.
  const day = ISO_DAY.exec(trimmed);

  return day
    ? Date.UTC(Number(day[1]), Number(day[2]) - 1, Number(day[3]))
    : undefined;
}

/** The bucket a row falls into, the way the store buckets it (`group_key`). */
function groupKeyOf(
  value: JSONValue | undefined,
  grouping: AggregateGrouping,
): string {
  if (value === undefined || value === null) {
    return '';
  }

  // A select column's first tag, so the groups still add up to the total.
  if (Array.isArray(value)) {
    const first = value[0];

    return typeof first === 'string' ? first : '';
  }

  const granularity = grouping.granularity ?? 'exact';

  if (typeof value === 'number') {
    if (granularity === 'exact') {
      return String(value);
    }

    const shifted = new Date(
      value + (grouping.tz_offset_minutes ?? 0) * 60_000,
    ).toISOString();

    return granularity === 'month' ? shifted.slice(0, 7) : shifted.slice(0, 10);
  }

  if (typeof value === 'string' && ISO_DAY.test(value)) {
    return granularity === 'month' ? value.slice(0, 7) : value;
  }

  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

/** Running state of one statistic: the store's `Accumulator`. */
class Accumulator {
  sum = 0;
  count = 0;
  min: number | undefined;
  max: number | undefined;

  add(number: number) {
    this.sum += number;
    this.count += 1;
    this.min = this.min === undefined ? number : Math.min(this.min, number);
    this.max = this.max === undefined ? number : Math.max(this.max, number);
  }

  finish(fn: AggregateFunction): number | null {
    if (fn === 'count') return this.count;
    if (this.count === 0) return null;
    if (fn === 'sum') return this.sum;
    if (fn === 'avg') return this.sum / this.count;

    return (fn === 'min' ? this.min : this.max) ?? null;
  }
}

const compareKeys = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * Computes an aggregation over rows the client already holds, by the rules the
 * store applies to a query (`aggregate.rs`, `Db::aggregate`): `count` counts the
 * rows that have a value (every row when it names nothing), the other functions
 * skip rows without a number, and a computed column is evaluated per row.
 *
 * For the rows the quick filter leaves, which the store cannot be asked about:
 * under a quick filter the totals describe the rows on screen.
 */
export function aggregateRows(
  rows: Iterable<RowValueReader>,
  aggregation: Aggregation,
): AggregateOutcome[] {
  const { aggregates, group_by: grouping } = aggregation;
  const now = aggregation.now_ms ?? Date.now();
  const totals = aggregates.map(() => new Accumulator());
  const perGroup = aggregates.map(() => new Map<string, Accumulator>());

  for (const read of rows) {
    const group = grouping ? groupKeyOf(read(grouping.property), grouping) : '';

    aggregates.forEach((aggregate, index) => {
      let present = true;
      let number: number | undefined;

      if (aggregate.expression) {
        // An expression is a computed column's kind and arguments, flattened
        // (`toExpression`), so the column's own generator evaluates it.
        const { kind, ...args } = aggregate.expression as {
          kind: DerivedColumnKind;
        } & Record<string, DerivedColumnArg>;
        const values: ArgValues = {};

        for (const arg of Object.values(args)) {
          if (typeof arg === 'string' && arg !== '') {
            values[arg] = read(arg);
          }
        }

        number = DERIVED_COLUMN_GENERATORS[kind]?.compute(values, args, now);
        present = number !== undefined;
      } else if (aggregate.property) {
        const value = read(aggregate.property);
        present = value !== undefined && value !== null;
        number = valueAsNumber(value);
      }

      const accumulate = (acc: Accumulator) => {
        if (aggregate.function === 'count') {
          if (present) acc.count += 1;

          return;
        }

        if (number !== undefined) acc.add(number);
      };

      accumulate(totals[index]);

      if (grouping) {
        let acc = perGroup[index].get(group);

        if (!acc) {
          acc = new Accumulator();
          perGroup[index].set(group, acc);
        }

        accumulate(acc);
      }
    });
  }

  return aggregates.map((aggregate, index): AggregateOutcome => {
    const outcome: AggregateOutcome = {
      id: aggregate.id,
      property: aggregate.property,
      function: aggregate.function,
      value: totals[index].finish(aggregate.function),
      count: totals[index].count,
    };

    if (!grouping) {
      return outcome;
    }

    const groups: AggregateGroup[] = [...perGroup[index]].map(([key, acc]) => ({
      key,
      value: acc.finish(aggregate.function),
      count: acc.count,
    }));

    // Chronological for day and month buckets, biggest-first otherwise.
    if ((grouping.granularity ?? 'exact') === 'exact') {
      groups.sort(
        (a, b) =>
          (b.value ?? -Infinity) - (a.value ?? -Infinity) ||
          compareKeys(a.key, b.key),
      );
    } else {
      groups.sort((a, b) => compareKeys(a.key, b.key));
    }

    const limit = grouping.limit ?? DEFAULT_GROUP_LIMIT;

    return {
      ...outcome,
      groups: groups.slice(0, limit),
      groups_truncated: groups.length > limit,
    };
  });
}
