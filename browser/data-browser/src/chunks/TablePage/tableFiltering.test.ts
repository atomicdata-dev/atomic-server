import { describe, expect, it } from 'vitest';
import {
  derivedFilterKey,
  filterKey,
  parseFilterKey,
  splitFilters,
  type TableFilter,
} from './tableFiltering';
import type { DerivedColumnSpec } from './derivedColumns';

const START = 'https://example.com/start';
const END = 'https://example.com/end';
const WATERED = 'https://example.com/watered';
const INTERVAL = 'https://example.com/interval';

const duration: DerivedColumnSpec = {
  id: 'duration',
  label: 'Duration',
  formula: 'coalesce(end, now()) - start',
  vars: { start: START, end: END },
  valueKind: 'duration',
};

const nextWater: DerivedColumnSpec = {
  id: 'next-water',
  label: 'Next water',
  formula: 'addDays(watered, interval)',
  vars: { watered: WATERED, interval: INTERVAL },
  valueKind: 'date',
};

const birthdaySoon: DerivedColumnSpec = {
  id: 'birthday-soon',
  label: 'Birthday soon',
  formula: 'daysUntilAnniversary(birthday) <= 14',
  vars: { birthday: 'https://example.com/birthday' },
  valueKind: 'boolean',
};

const total: DerivedColumnSpec = {
  id: 'total',
  label: 'Total',
  formula: 'quantity * price',
  vars: { quantity: START, price: END },
};

const NOW = 1_700_000_000_000;

describe('filter keys', () => {
  it('names a stored column by its subject and a computed one by its id', () => {
    expect(filterKey({ property: START, operator: 'eq', value: '' })).toBe(
      START,
    );
    expect(filterKey({ derived: 'duration', operator: 'gte', value: '' })).toBe(
      'derived:duration',
    );
  });

  it('round-trips', () => {
    expect(parseFilterKey(START)).toEqual({ property: START });
    expect(parseFilterKey(derivedFilterKey('duration'))).toEqual({
      derived: 'duration',
    });
  });
});

describe('splitFilters', () => {
  it('keeps stored constraints on the indexed side', () => {
    const filters: TableFilter[] = [
      { property: START, operator: 'gt', value: '5' },
    ];
    const { propVals, expressionFilters } = splitFilters(filters, [], NOW);

    expect(propVals).toEqual([{ property: START, value: '5', operator: 'gt' }]);
    expect(expressionFilters).toEqual([]);
  });

  it('sends a duration filter in milliseconds, having asked for hours', () => {
    const filters: TableFilter[] = [
      { derived: 'duration', operator: 'gt', value: '1.5' },
    ];
    const { expressionFilters } = splitFilters(filters, [duration], NOW);

    expect(expressionFilters).toEqual([
      {
        expression: {
          kind: 'formula',
          formula: 'coalesce(end, now()) - start',
          vars: { start: START, end: END },
        },
        operator: 'gt',
        value: 5_400_000,
        // A running entry measures against the clock, so the query carries one.
        now_ms: NOW,
        tz_offset_minutes: -new Date().getTimezoneOffset(),
      },
    ]);
  });

  it('compares a due date against the moment the query runs', () => {
    const filters: TableFilter[] = [
      { derived: 'next-water', operator: 'lte', value: 'now' },
    ];
    const { expressionFilters } = splitFilters(filters, [nextWater], NOW);

    // "Due" has to mean now-at-query-time; a date typed once goes stale tomorrow.
    expect(expressionFilters[0].value).toBe(NOW);
    expect(expressionFilters[0].now_ms).toBe(NOW);
  });

  it('takes a fixed date for a date-valued column too', () => {
    const filters: TableFilter[] = [
      { derived: 'next-water', operator: 'lte', value: '2026-08-05' },
    ];
    const { expressionFilters } = splitFilters(filters, [nextWater], NOW);

    expect(expressionFilters[0].value).toBe(Date.parse('2026-08-05'));
  });

  it('compares a true/false column as 1 or 0, against the same clock as its cells', () => {
    const filters: TableFilter[] = [
      { derived: 'birthday-soon', operator: 'eq', value: '1' },
    ];
    const { expressionFilters } = splitFilters(filters, [birthdaySoon], NOW);

    expect(expressionFilters).toMatchObject([
      { operator: 'eq', value: 1, now_ms: NOW },
    ]);
  });

  it('leaves the clock out of a filter on plain arithmetic', () => {
    const filters: TableFilter[] = [
      { derived: 'total', operator: 'gt', value: '100' },
    ];
    const { expressionFilters } = splitFilters(filters, [total], NOW);

    expect(expressionFilters).toMatchObject([{ operator: 'gt', value: 100 }]);
    expect(expressionFilters[0].now_ms).toBeUndefined();
  });

  it('skips a filter that has no value yet', () => {
    // Its chip stays visible while being edited; the table must not blank out.
    const filters: TableFilter[] = [
      { property: START, operator: 'eq', value: '' },
      { derived: 'duration', operator: 'gte', value: '' },
    ];
    const result = splitFilters(filters, [duration], NOW);

    expect(result.propVals).toEqual([]);
    expect(result.expressionFilters).toEqual([]);
  });

  it('skips a filter whose computed column is gone or incomplete', () => {
    const filters: TableFilter[] = [
      { derived: 'duration', operator: 'gte', value: '2' },
    ];

    // Asking anyway would narrow to nothing and read as a broken table.
    expect(splitFilters(filters, [], NOW).expressionFilters).toEqual([]);
    expect(
      splitFilters(filters, [{ ...duration, formula: ' ' }], NOW)
        .expressionFilters,
    ).toEqual([]);
  });

  it('skips a value that is not a number', () => {
    const filters: TableFilter[] = [
      { derived: 'duration', operator: 'gte', value: 'soon' },
    ];

    expect(splitFilters(filters, [duration], NOW).expressionFilters).toEqual(
      [],
    );
  });
});
