import { describe, it, expect } from 'vitest';
import { Datatype, type JSONValue, type Property } from '@tomic/react';
import {
  aggregateRows,
  defaultGranularity,
  formatAggregateValue,
  formatGroupKey,
  isGroupableProperty,
  parseAggregates,
  propertiesForFunction,
  toAggregation,
  BREAKDOWN_ROWS_ID,
} from './tableAggregates';

const property = (datatype: Datatype, shortname = 'x'): Property =>
  ({
    subject: `https://example.com/property/${shortname}`,
    datatype,
    shortname,
  }) as Property;

const AMOUNT = property(Datatype.INTEGER, 'amount');
const RATE = property(Datatype.FLOAT, 'rate');
const START = property(Datatype.TIMESTAMP, 'start');
const DAY = property(Datatype.DATE, 'day');
const TITLE = property(Datatype.STRING, 'title');
const STATUS = property(Datatype.RESOURCEARRAY, 'status');

describe('which columns a function accepts', () => {
  const all = [AMOUNT, RATE, START, DAY, TITLE, STATUS];

  it('sums and averages numbers only', () => {
    expect(propertiesForFunction(all, 'sum')).toEqual([AMOUNT, RATE]);
    expect(propertiesForFunction(all, 'avg')).toEqual([AMOUNT, RATE]);
  });

  it('takes the earliest/latest of dates as well as numbers', () => {
    expect(propertiesForFunction(all, 'min')).toEqual([
      AMOUNT,
      RATE,
      START,
      DAY,
    ]);
  });

  it('counts anything — it counts the rows that have a value', () => {
    expect(propertiesForFunction(all, 'count')).toEqual(all);
  });
});

describe('which columns can be broken down by', () => {
  it('offers bounded and bucketable columns', () => {
    expect(isGroupableProperty(STATUS)).toBe(true);
    expect(isGroupableProperty(START)).toBe(true);
    expect(isGroupableProperty(DAY)).toBe(true);
    // A free-text column would give one bucket per row.
    expect(isGroupableProperty(TITLE)).toBe(false);
    expect(isGroupableProperty(AMOUNT)).toBe(false);
  });

  it('buckets timestamps per day by default', () => {
    // Grouping a timestamp by its exact value is one group per row.
    expect(defaultGranularity(START)).toBe('day');
    expect(defaultGranularity(STATUS)).toBe('exact');
  });
});

describe('toAggregation', () => {
  const sumAmount = {
    id: 'sum',
    property: AMOUNT.subject,
    function: 'sum' as const,
  };

  it('is undefined with nothing to compute, so the query stays cheap', () => {
    expect(toAggregation([], undefined, 'day')).toBeUndefined();
  });

  it('passes the aggregates through, without a breakdown', () => {
    expect(toAggregation([sumAmount], undefined, 'day')).toEqual({
      aggregates: [{ id: 'sum', property: AMOUNT.subject, function: 'sum' }],
      group_by: undefined,
    });
  });

  it('counts every row alongside a breakdown, for its row counts', () => {
    // A sum's per-group count is only the rows that had a number, so a
    // breakdown of tasks without an Estimate read "0 rows" under each status.
    const aggregation = toAggregation([sumAmount], STATUS.subject, 'exact');

    expect(aggregation?.aggregates).toEqual([
      { id: 'sum', property: AMOUNT.subject, function: 'sum' },
      { id: BREAKDOWN_ROWS_ID, function: 'count' },
    ]);
    expect(aggregation?.group_by?.property).toBe(STATUS.subject);
  });

  describe('over a computed column', () => {
    const duration = {
      id: 'duration',
      label: 'Duration',
      kind: 'elapsed' as const,
      args: { from: START.subject, until: 'https://example.com/end' },
    };
    const sumDuration = {
      id: 'sum-duration-0',
      derived: 'duration',
      function: 'sum' as const,
    };

    it('sends the column expression for the store to evaluate', () => {
      const aggregation = toAggregation([sumDuration], undefined, 'day', [
        duration,
      ]);

      expect(aggregation?.aggregates).toEqual([
        {
          id: 'sum-duration-0',
          function: 'sum',
          expression: {
            kind: 'elapsed',
            from: START.subject,
            until: 'https://example.com/end',
          },
        },
      ]);
    });

    it('measures a live value against a whole minute, not this instant', () => {
      const aggregation = toAggregation([sumDuration], undefined, 'day', [
        duration,
      ]);

      // `now_ms` is part of the query's identity, so it must not change on every
      // render — that would re-run the query continuously.
      expect(aggregation?.now_ms).toBe(
        Math.floor(Date.now() / 60_000) * 60_000,
      );
    });

    it('leaves the clock out when nothing measures against it', () => {
      const total = {
        id: 'total',
        label: 'Total',
        kind: 'product' as const,
        args: { a: AMOUNT.subject, b: 2 },
      };
      const aggregation = toAggregation(
        [{ id: 'sum-total-0', derived: 'total', function: 'sum' }],
        undefined,
        'day',
        [total],
      );

      expect(aggregation?.now_ms).toBeUndefined();
    });

    it('asks for nothing when the column it names is gone', () => {
      // A total left behind by a removed column would otherwise render as an
      // empty number forever.
      expect(
        toAggregation([sumDuration], undefined, 'day', []),
      ).toBeUndefined();
    });

    it('asks for nothing when the column is still incomplete', () => {
      const halfBuilt = { ...duration, args: { from: '' } };

      expect(
        toAggregation([sumDuration], undefined, 'day', [halfBuilt]),
      ).toBeUndefined();
    });
  });

  it('sends the local timezone offset with a breakdown', () => {
    const aggregation = toAggregation([sumAmount], START.subject, 'day');

    expect(aggregation?.group_by).toEqual({
      property: START.subject,
      granularity: 'day',
      // Days must be the user's days: a 23:30 entry belongs to the day they
      // were living, not to UTC's.
      tz_offset_minutes: -new Date().getTimezoneOffset(),
    });
  });
});

describe('parseAggregates', () => {
  const valid = { id: 'sum', property: AMOUNT.subject, function: 'sum' };

  it('reads the stored array', () => {
    expect(parseAggregates([valid])).toEqual([valid]);
  });

  it('drops malformed entries rather than throwing', () => {
    expect(
      parseAggregates([
        valid,
        { ...valid, function: 'median' },
        { property: AMOUNT.subject },
        'nonsense',
      ] as unknown as JSONValue),
    ).toEqual([valid]);
  });

  it('is empty for unset config', () => {
    expect(parseAggregates(undefined)).toEqual([]);
  });
});

describe('formatting', () => {
  it('shows nothing-to-compute as a dash, not as zero', () => {
    expect(formatAggregateValue(null, 'sum', AMOUNT)).toBe('—');
    expect(formatAggregateValue(0, 'sum', AMOUNT)).toBe('0');
  });

  it('formats the earliest of a date column as a date', () => {
    const stamp = Date.parse('2026-07-30T12:00:00Z');

    expect(formatAggregateValue(stamp, 'min', START)).toContain('2026');
    // A sum of the same numbers is a number, not a date.
    expect(formatAggregateValue(stamp, 'sum', START)).not.toContain('2026-');
  });

  it('labels the bucket that has no value', () => {
    expect(formatGroupKey('', 'exact')).toBe('(none)');
  });

  it('formats day and month buckets, and leaves other keys alone', () => {
    expect(formatGroupKey('2026-07-30', 'day')).toContain('2026');
    expect(formatGroupKey('2026-07', 'month')).toContain('2026');
    expect(formatGroupKey('true', 'exact')).toBe('true');
  });
});

describe('formatAggregateValue precision', () => {
  const amount = property(Datatype.FLOAT, 'amount');

  it('does not show a small nonzero total as zero', () => {
    expect(formatAggregateValue(0.0000375, 'sum', amount)).toBe('0.0000375');
    expect(formatAggregateValue(0.00001875, 'avg', amount)).toBe('0.0000188');
  });

  it('keeps two decimals for ordinary totals and a real zero', () => {
    expect(formatAggregateValue(1.2500125, 'sum', amount)).toBe('1.25');
    expect(formatAggregateValue(0, 'sum', amount)).toBe('0');
  });
});

describe('aggregateRows', () => {
  const Q = 'https://example.com/property/quantity';
  const P = 'https://example.com/property/price';
  const TAG = 'https://example.com/property/tag';
  const DUE = 'https://example.com/property/due';

  const rows = [
    { [Q]: 2, [P]: 5, [TAG]: ['a'], [DUE]: '2026-07-01' },
    { [Q]: 3, [TAG]: ['b', 'a'], [DUE]: '2026-07-20' },
    { [P]: '4', [TAG]: ['a'], [DUE]: '2026-08-02' },
  ].map(row => (prop: string) => (row as Record<string, JSONValue>)[prop]);

  const byId = (outcomes: ReturnType<typeof aggregateRows>) =>
    Object.fromEntries(outcomes.map(o => [o.id, o]));

  it('follows the store: counts rows with a value, skips rows without a number', () => {
    const out = byId(
      aggregateRows(rows, {
        aggregates: [
          { id: 'rows', function: 'count' },
          { id: 'sumQ', property: Q, function: 'sum' },
          { id: 'avgQ', property: Q, function: 'avg' },
          { id: 'countQ', property: Q, function: 'count' },
          // A numeric string still sums, as it does in the store.
          { id: 'sumP', property: P, function: 'sum' },
          { id: 'latest', property: DUE, function: 'max' },
          {
            id: 'amount',
            expression: { kind: 'product', a: Q, b: P },
            function: 'sum',
          },
        ],
      }),
    );

    expect(out.rows.value).toBe(3);
    expect(out.sumQ).toMatchObject({ value: 5, count: 2 });
    expect(out.avgQ.value).toBe(2.5);
    expect(out.countQ.value).toBe(2);
    expect(out.sumP.value).toBe(9);
    expect(out.latest.value).toBe(Date.UTC(2026, 7, 2));
    // Only the first row has both a quantity and a price.
    expect(out.amount).toMatchObject({ value: 10, count: 1 });
  });

  it('has no value, rather than zero, when nothing contributed', () => {
    const [sum, count] = aggregateRows([], {
      aggregates: [{ property: Q, function: 'sum' }, { function: 'count' }],
    });

    expect(sum.value).toBeNull();
    expect(count.value).toBe(0);
  });

  it('breaks down by the first tag, and by month', () => {
    const [byTag] = aggregateRows(rows, {
      aggregates: [{ property: Q, function: 'sum' }],
      group_by: { property: TAG },
    });

    expect(byTag.groups).toEqual([
      { key: 'b', value: 3, count: 1 },
      { key: 'a', value: 2, count: 1 },
    ]);

    const [byMonth] = aggregateRows(rows, {
      aggregates: [{ function: 'count' }],
      group_by: { property: DUE, granularity: 'month' },
    });

    expect(byMonth.groups).toEqual([
      { key: '2026-07', value: 2, count: 2 },
      { key: '2026-08', value: 1, count: 1 },
    ]);
  });
});

describe('formatAggregateValue for an empty answer', () => {
  it('reads a count over no rows as 0, but not a sum, and not an unanswered one', () => {
    expect(formatAggregateValue(null, 'count', undefined)).toBe('0');
    expect(formatAggregateValue(null, 'sum', undefined)).toBe('—');
    expect(formatAggregateValue(undefined, 'count', undefined)).toBe('—');
  });
});
