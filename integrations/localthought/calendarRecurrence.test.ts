import { expect, it } from 'vitest';
import { Datatype } from '../../browser/lib/src/index';
import { calendarRecurrenceProjection } from './calendarRecurrence';
import { calendarRecurrenceShortname as prop } from '../../browser/lib/src/calendar-recurrence';
import type { FetchedPlatform } from './schema';
const data = (
  values: FetchedPlatform['records'][number]['values'],
): FetchedPlatform => ({
  platform: 'google-calendar',
  ontology: {
    description: '',
    terms: [
      {
        path: 'event',
        shortname: 'event',
        kind: 'class',
        datatype: Datatype.JSON,
        description: '',
        requires: [],
        recommends: [],
      },
    ],
  },
  records: [
    {
      id: 'event',
      namespace: 'calendar-a',
      resource: 'event',
      name: 'Meeting',
      values,
    },
  ],
});
it('retains source identity, rules and offsets without mutating provider fields', () => {
  const input = data({
    start: {
      dateTime: '2026-03-22T09:00:00+01:00',
      timeZone: 'Europe/Amsterdam',
    },
    end: { dateTime: '2026-03-22T10:00:00+01:00' },
    recurrence: ['RRULE:FREQ=WEEKLY;COUNT=3'],
  });
  expect(calendarRecurrenceProjection(input).records[0].values[prop]).toEqual({
    calendarId: 'calendar-a',
    event: { id: 'event', ...input.records[0].values },
  });
  expect(input.records[0].values[prop]).toBeUndefined();
});
it('accepts minimal cancellation tombstones with normalized provider names', () => {
  const input = data({
    status: 'cancelled',
    'recurring-event-id': 'series',
    'original-start-time': { dateTime: '2026-03-22T08:00:00Z' },
  });
  expect(
    calendarRecurrenceProjection(input).records[0].values[prop],
  ).toMatchObject({
    event: {
      recurringEventId: 'series',
      originalStartTime: { dateTime: '2026-03-22T08:00:00Z' },
      status: 'cancelled',
    },
  });
});
it('fails closed when a provider omits instance identity', () => {
  expect(() =>
    calendarRecurrenceProjection(data({ 'recurring-event-id': 'series' })),
  ).toThrow(/originalStartTime/);
});
it('leaves all-day expansion to the civil-date adapter and clears former timed state', () => {
  expect(
    calendarRecurrenceProjection(data({ start: { date: '2026-03-22' } }))
      .records[0].values[prop],
  ).toEqual({});
});
