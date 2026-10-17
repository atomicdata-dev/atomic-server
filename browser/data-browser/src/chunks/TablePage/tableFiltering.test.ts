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
  kind: 'elapsed',
  args: { from: START, until: END },
};

const nextWater: DerivedColumnSpec = {
  id: 'next-water',
  label: 'Next water',
  kind: 'offset',
  args: { from: WATERED, days: INTERVAL },
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
        expression: { kind: 'elapsed', from: START, until: END },
        operator: 'gt',
        value: 5_400_000,
        // A running entry measures against the clock, so the query carries one.
        now_ms: NOW,
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
      splitFilters(filters, [{ ...duration, args: { from: '' } }], NOW)
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
