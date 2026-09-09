import { expect, it } from 'vitest';
import {
  calendarOccurrenceBuckets,
  calendarPropertyMatches,
} from './calendarOccurrences';
it('matches both projected and native calendar fields, not unrelated dates', () => {
  expect(
    calendarPropertyMatches(
      'lt-google-calendar-property-atomic-calendar-day',
      'atomic-calendar-day',
    ),
  ).toBe(true);
  expect(
    calendarPropertyMatches('atomic-calendar-day', 'atomic-calendar-day'),
  ).toBe(true);
  expect(
    calendarPropertyMatches(
      'custom-atomic-calendar-day',
      'atomic-calendar-day',
    ),
  ).toBe(false);
});
it('buckets civil dates near offset boundaries and clips multi-day occurrences', () => {
  const records = [
    {
      calendarId: 'c',
      subject: 'timed',
      event: {
        id: 'timed',
        start: {
          dateTime: '2026-03-29T00:30:00+14:00',
          timeZone: 'Pacific/Kiritimati',
        },
        end: { dateTime: '2026-03-29T01:30:00+14:00' },
        recurrence: ['RRULE:FREQ=DAILY;COUNT=2'],
      },
    },
    {
      calendarId: 'c',
      subject: 'all-day',
      event: {
        id: 'all-day',
        start: { date: '2026-03-27' },
        end: { date: '2026-03-30' },
        recurrence: ['RRULE:FREQ=WEEKLY;COUNT=1'],
      },
    },
  ];
  const buckets = calendarOccurrenceBuckets(records, [
    '2026-03-28',
    '2026-03-29',
    '2026-03-30',
  ]);
  expect(buckets.get('2026-03-28')?.map(x => x.subject)).toEqual(['all-day']);
  expect(buckets.get('2026-03-29')?.map(x => x.subject)).toEqual([
    'all-day',
    'timed',
  ]);
  expect(buckets.get('2026-03-30')?.map(x => x.subject)).toEqual(['timed']);
});
