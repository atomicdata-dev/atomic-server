import { beforeAll, describe, it, expect } from 'vitest';
import type { JSONValue } from '@tomic/react';
import {
  bindFormula,
  columnSlug,
  columnSlugs,
  computeDerived,
  dependsOnNow,
  formatDerivedValue,
  formulaIdentifiers,
  inferValueKind,
  isLive,
  parseDerivedColumnSpecs,
  readInstant,
  specFromFormula,
  type DerivedColumnSpec,
} from './derivedColumns';
import { validateFormula } from './formulaEngine';
import { useRealFormulaEngine } from './formulaEngine.testing';
import { TABLE_TEMPLATES } from './tableTemplates';

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

const START = 'https://example.com/property/start';
const END = 'https://example.com/property/end';
const QUANTITY = 'https://example.com/property/quantity';
const PRICE = 'https://example.com/property/price';
const LAST_DONE = 'https://example.com/property/last-done';
const BIRTHDAY = 'https://example.com/property/birthday';

// Noon on the 30th wherever the tests run: dates are read in the local zone.
const NOW = new Date(2026, 6, 30, 12).getTime();

const spec = (
  formula: string,
  vars: Record<string, string>,
  valueKind?: DerivedColumnSpec['valueKind'],
): DerivedColumnSpec => ({ id: 'x', label: 'X', formula, vars, valueKind });

beforeAll(useRealFormulaEngine);

describe('computing a formula over a row', () => {
  const duration = spec(
    'coalesce(end, now()) - start',
    { start: START, end: END },
    'duration',
  );

  it('is the span between two properties, and ticks while the end is empty', () => {
    expect(
      computeDerived(duration, { [START]: NOW - HOUR, [END]: NOW }, NOW),
    ).toBe(HOUR);
    expect(computeDerived(duration, { [START]: NOW - 5 * MINUTE }, NOW)).toBe(
      5 * MINUTE,
    );
    expect(
      formatDerivedValue(
        duration,
        computeDerived(duration, { [START]: NOW - HOUR, [END]: NOW }, NOW)!,
      ),
    ).toBe('1:00:00');
  });

  it('is empty without the inputs it needs', () => {
    expect(computeDerived(duration, {}, NOW)).toBeUndefined();
    expect(
      computeDerived(
        spec('end - start', { start: START, end: END }),
        { [START]: NOW },
        NOW,
      ),
    ).toBeUndefined();
  });

  it('counts whole days, and reads DATE properties too', () => {
    const since = spec('days(now() - d)', { d: LAST_DONE }, 'days');

    expect(computeDerived(since, { [LAST_DONE]: NOW - 3 * DAY }, NOW)).toBe(3);
    // A DATE property stores an ISO day rather than a number of millis.
    expect(computeDerived(since, { [LAST_DONE]: '2026-07-27' }, NOW)).toBe(3);
  });

  it('multiplies, with a fixed factor if you like', () => {
    const q = { [QUANTITY]: 4, [PRICE]: 25 };

    expect(
      computeDerived(
        spec('quantity * price', { quantity: QUANTITY, price: PRICE }),
        q,
        NOW,
      ),
    ).toBe(100);
    expect(
      computeDerived(spec('quantity * 85', { quantity: QUANTITY }), q, NOW),
    ).toBe(340);
  });

  it('moves a date by days', () => {
    expect(
      computeDerived(
        spec('addDays(d, 14)', { d: LAST_DONE }),
        { [LAST_DONE]: NOW },
        NOW,
      ),
    ).toBe(NOW + 14 * DAY);
  });

  it('counts a date stamped today as today, in any time zone', () => {
    const sinceDate = spec('days(now() - d)', { d: LAST_DONE }, 'days');
    const today = new Date(2026, 6, 30);
    const stamped = `${today.getFullYear()}-07-30`;
    // 00:30 local on the stamped day, which east of UTC is still the day before in UTC.
    const justAfterMidnight = new Date(2026, 6, 30, 0, 30).getTime();

    expect(
      computeDerived(sinceDate, { [LAST_DONE]: stamped }, justAfterMidnight),
    ).toBe(0);
  });

  it('shows a date a formula moved on the day it lands, in any season', () => {
    const next = spec('addDays(d, 7)', { d: LAST_DONE }, 'date');
    const value = computeDerived(next, { [LAST_DONE]: '2026-01-15' }, NOW);

    expect(formatDerivedValue(next, value as number)).toBe(
      new Date(Date.UTC(2026, 0, 22)).toLocaleDateString(undefined, {
        timeZone: 'UTC',
      }),
    );
  });

  it('knows how far away a birthday is', () => {
    const days = spec('daysUntilAnniversary(birthday)', { birthday: BIRTHDAY });
    const soon = spec(
      'daysUntilAnniversary(birthday) <= 14',
      { birthday: BIRTHDAY },
      'boolean',
    );

    // Born 2000-08-05, "now" is 2026-07-30: six days to go.
    const values = { [BIRTHDAY]: '2000-08-05' };

    expect(computeDerived(days, values, NOW)).toBe(6);
    expect(computeDerived(soon, values, NOW)).toBe(1);
    expect(computeDerived(soon, { [BIRTHDAY]: '2000-03-05' }, NOW)).toBe(0);
    expect(formatDerivedValue(soon, 1)).toBe('✓');
    expect(formatDerivedValue(soon, 0)).toBe('');
  });
});

describe('formatting', () => {
  it('reads a days-since as a distance', () => {
    const days = { valueKind: 'days' as const };

    expect(formatDerivedValue(days, 0)).toBe('today');
    expect(formatDerivedValue(days, 3)).toBe('3d ago');
    expect(formatDerivedValue(days, -5)).toBe('in 5d');
  });

  it('keeps two decimals unless the amount is whole', () => {
    expect(formatDerivedValue({}, 75)).toBe('75');
    expect(formatDerivedValue({}, 127.5)).toBe('127.50');
  });
});

describe('how a typed formula is shown', () => {
  it('guesses from its shape', () => {
    expect(inferValueKind('daysUntilAnniversary(b) <= 14', false)).toBe(
      'boolean',
    );
    expect(inferValueKind('end - start', true)).toBe('duration');
    expect(inferValueKind('coalesce(end, now()) - start', true)).toBe(
      'duration',
    );
    expect(inferValueKind('end - start', false)).toBeUndefined();
    expect(inferValueKind('days(now() - d)', true)).toBe('days');
    expect(inferValueKind('addDays(d, 7)', true)).toBe('date');
    expect(inferValueKind('quantity * price', false)).toBeUndefined();
  });
});

describe('what ticks', () => {
  it('only a running duration is live', () => {
    expect(isLive(spec('coalesce(e, now()) - s', {}, 'duration'))).toBe(true);
    expect(isLive(spec('days(now() - d)', {}, 'days'))).toBe(false);
    expect(isLive(spec('e - s', {}, 'duration'))).toBe(false);
  });

  it('reading the clock is what makes a query time-dependent', () => {
    expect(dependsOnNow(spec('now() - s', {}))).toBe(true);
    expect(dependsOnNow(spec('daysUntilAnniversary(d)', {}))).toBe(true);
    expect(dependsOnNow(spec('a * b', {}))).toBe(false);
  });
});

describe('naming columns in a formula', () => {
  it('slugs a label into an identifier', () => {
    expect(columnSlug('Last watered')).toBe('last_watered');
    expect(columnSlug('Meat & fish')).toBe('meat_fish');
    expect(columnSlug('2nd try')).toBe('c2nd_try');
    expect(columnSlug('!!!')).toBe('column');
  });

  it('suffixes a collision, and keeps one entry for the same column', () => {
    expect(
      columnSlugs([
        ['Price', 'a'],
        ['price', 'a'],
        ['PRICE', 'b'],
        ['Price!', 'c'],
      ]),
    ).toEqual({ price: 'a', price_2: 'b', price_3: 'c' });
  });

  it('finds the columns a formula reads, not functions or literals', () => {
    expect(
      formulaIdentifiers(
        'if(a > 1.5e3 && !flag, math::floor(b), coalesce(a, now()))',
      ),
    ).toEqual(['a', 'flag', 'b']);
  });

  it('binds them, and suggests the closest column for a typo', () => {
    const slugs = { last_done: LAST_DONE, interval: QUANTITY };

    expect(bindFormula('addDays(last_done, interval)', slugs)).toEqual({
      vars: { last_done: LAST_DONE, interval: QUANTITY },
      unknown: [],
    });
    expect(bindFormula('addDays(last_dne, interval)', slugs).unknown).toEqual([
      ['last_dne', 'last_done'],
    ]);
    expect(bindFormula('xyzzy + 1', slugs).unknown).toEqual([
      ['xyzzy', undefined],
    ]);
  });

  it('builds a spec', () => {
    expect(
      specFromFormula(
        'Next due',
        'addDays(last_done, 7)',
        { last_done: LAST_DONE },
        { valueKind: 'date' },
      ),
    ).toEqual({
      id: 'next-due',
      label: 'Next due',
      formula: 'addDays(last_done, 7)',
      vars: { last_done: LAST_DONE },
      valueKind: 'date',
    });
  });
});

describe('the store’s validation', () => {
  const check = (formula: string, vars: Record<string, string> = {}) =>
    validateFormula({ kind: 'formula', formula, vars });

  it('accepts a formula and explains a broken one', () => {
    expect(check('a + 1', { a: START })).toBeNull();
    expect(check('a +', { a: START })).toEqual(expect.any(String));
    expect(check('nope(1)')).toEqual(expect.any(String));
  });

  it('accepts every template’s computed columns', () => {
    for (const template of TABLE_TEMPLATES) {
      for (const view of template.spec?.views ?? []) {
        for (const derived of view.derivedColumns ?? []) {
          const columns = (template.spec?.columns ?? []).map(
            c => [c.name, c.name] as [string, string],
          );
          const { vars } = bindFormula(derived.formula, columnSlugs(columns));

          expect(check(derived.formula, vars), derived.name).toBeNull();
        }
      }
    }
  });
});

describe('parseDerivedColumnSpecs', () => {
  const stored = {
    id: 'duration',
    label: 'Duration',
    formula: 'coalesce(end, now()) - start',
    vars: { start: START, end: END },
    valueKind: 'duration',
  };

  it('reads the stored array', () => {
    expect(parseDerivedColumnSpecs([stored])).toEqual([stored]);
  });

  it('converts the five older kinds to the formulas the store converts them to', () => {
    const legacy = (kind: string, args: Record<string, JSONValue>) =>
      parseDerivedColumnSpecs([{ id: 'x', label: 'X', kind, args }])[0];

    expect(legacy('difference', { from: START, to: END })).toMatchObject({
      formula: 'v1 - v0',
      vars: { v0: START, v1: END },
      valueKind: 'duration',
    });
    expect(legacy('elapsed', { from: START, until: END })).toMatchObject({
      formula: 'coalesce(v1, now()) - v0',
      vars: { v0: START, v1: END },
    });
    expect(legacy('elapsed', { from: START })).toMatchObject({
      formula: 'now() - v0',
      vars: { v0: START },
    });
    expect(legacy('daysSince', { from: START })).toMatchObject({
      formula: 'days(now() - v0)',
      valueKind: 'days',
    });
    expect(legacy('product', { a: QUANTITY, b: 85 })).toMatchObject({
      formula: 'v0 * (85.0)',
      vars: { v0: QUANTITY },
    });
    expect(legacy('offset', { from: LAST_DONE, days: PRICE })).toMatchObject({
      formula: 'v0 + v1 * 86400000.0',
      valueKind: 'date',
    });
  });

  it('computes a converted spec', () => {
    const [offset] = parseDerivedColumnSpecs([
      {
        id: 'x',
        label: 'X',
        kind: 'offset',
        args: { from: LAST_DONE, days: 14 },
      },
    ]);

    expect(computeDerived(offset, { [LAST_DONE]: NOW }, NOW)).toBe(
      NOW + 14 * DAY,
    );
  });

  it('drops malformed specs rather than throwing', () => {
    // Config can be hand-written or assistant-written; a bad entry must not be
    // able to take the whole table down.
    expect(
      parseDerivedColumnSpecs([
        stored,
        { ...stored, vars: { a: { nested: true } } },
        { id: 'x', label: 'X', kind: 'nonsense', args: {} },
        { id: 'x', label: 'X', kind: 'difference', args: { from: START } },
        {
          id: 'x',
          label: 'X',
          kind: 'difference',
          args: { from: { nested: true }, to: END },
        },
        { label: 'No id' },
        'nonsense',
      ] as unknown as JSONValue),
    ).toEqual([stored]);
  });

  it('is empty for unset or non-array config', () => {
    expect(parseDerivedColumnSpecs(undefined)).toEqual([]);
    expect(parseDerivedColumnSpecs('{}' as unknown as JSONValue)).toEqual([]);
  });
});

describe('readInstant', () => {
  it('reads a civil date as local midnight, like a local timestamp', () => {
    expect(readInstant({ d: '2026-01-01' }, 'd')).toBe(
      new Date(2026, 0, 1).getTime(),
    );
  });

  it('still reads a full timestamp string', () => {
    expect(readInstant({ d: '2026-01-01T10:00:00.000Z' }, 'd')).toBe(
      Date.UTC(2026, 0, 1, 10),
    );
  });
});
