import { describe, expect, it } from 'vitest';
import {
  isCalendarDate,
  matchesCalendarField,
  isAllDayOnDate,
  nextCalendarDate,
} from './calendar-date';

describe('civil calendar dates', () => {
  it('validates real dates without accepting timestamp prefixes', () => {
    for (const date of ['2024-02-29', '2026-09-09', '0001-01-01'])
      expect(isCalendarDate(date)).toBe(true);
    for (const date of [
      '2026-02-29',
      '2026-04-31',
      '2026-13-01',
      '2026-09-09T00:00:00Z',
      '2026-9-9',
      '0000-01-01',
      undefined,
    ])
      expect(isCalendarDate(date)).toBe(false);
  });
  it('includes the start and excludes the end for single and multi-day events', () => {
    expect(isAllDayOnDate('2026-09-09', '2026-09-10', '2026-09-09')).toBe(true);
    expect(isAllDayOnDate('2026-09-09', '2026-09-10', '2026-09-10')).toBe(
      false,
    );
    for (const day of ['2024-02-28', '2024-02-29', '2024-03-01'])
      expect(isAllDayOnDate('2024-02-28', '2024-03-02', day)).toBe(true);
    expect(isAllDayOnDate('2024-02-28', '2024-03-02', '2024-03-02')).toBe(
      false,
    );
  });
  it('handles DST and year boundaries with no instant conversion', () => {
    expect(isAllDayOnDate('2026-03-28', '2026-03-31', '2026-03-29')).toBe(true);
    expect(isAllDayOnDate('2026-12-31', '2027-01-02', '2027-01-01')).toBe(true);
  });
  it('rejects invalid, missing, empty and reversed ranges', () => {
    for (const end of [undefined, '2026-09-09', '2026-09-08', '2026-09-31'])
      expect(isAllDayOnDate('2026-09-09', end, '2026-09-09')).toBe(false);
  });
});

it('creates exclusive one-day ends across leap days and years', () => {
  expect(nextCalendarDate('2024-02-28')).toBe('2024-02-29');
  expect(nextCalendarDate('2024-02-29')).toBe('2024-03-01');
  expect(nextCalendarDate('2026-12-31')).toBe('2027-01-01');
  expect(() => nextCalendarDate('2026-02-30')).toThrow();
});

it('matches installed Google property shortnames without adopting unrelated fields', () => {
  expect(
    matchesCalendarField('atomic-calendar-day', 'atomic-calendar-day'),
  ).toBe(true);
  expect(
    matchesCalendarField(
      'lt-google-calendar-property-atomic-calendar-day',
      'atomic-calendar-day',
    ),
  ).toBe(true);
  expect(
    matchesCalendarField('custom-atomic-calendar-day', 'atomic-calendar-day'),
  ).toBe(false);
  expect(matchesCalendarField(undefined, 'atomic-calendar-day')).toBe(false);
});
