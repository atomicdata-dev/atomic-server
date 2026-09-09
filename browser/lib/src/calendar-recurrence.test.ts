import { describe, expect, it } from 'vitest';
import {
  expandCalendar,
  validateCalendarEvent,
  type CalendarRecord,
} from './calendar-recurrence';

const series = (overrides = {}): CalendarRecord => ({
  calendarId: 'work',
  subject: 'series-row',
  event: {
    id: 'weekly',
    summary: 'Standup',
    start: {
      dateTime: '2026-03-22T09:00:00+01:00',
      timeZone: 'Europe/Amsterdam',
    },
    end: { dateTime: '2026-03-22T10:00:00+01:00' },
    recurrence: ['RRULE:FREQ=WEEKLY;COUNT=3'],
    ...overrides,
  },
});
const expand = (
  records: CalendarRecord[],
  from = '2026-03-01',
  to = '2026-05-01',
) => expandCalendar(records, Date.parse(from), Date.parse(to));

describe('timed calendar recurrence', () => {
  it('keeps wall time through spring DST and stops at COUNT', () => {
    expect(
      expand([series()]).map(x => new Date(x.start).toISOString()),
    ).toEqual([
      '2026-03-22T08:00:00.000Z',
      '2026-03-29T07:00:00.000Z',
      '2026-04-05T07:00:00.000Z',
    ]);
  });
  it('handles autumn DST independently of the host timezone', () => {
    const row = series({
      start: {
        dateTime: '2026-10-18T09:00:00+02:00',
        timeZone: 'Europe/Amsterdam',
      },
      end: { dateTime: '2026-10-18T10:00:00+02:00' },
    });
    expect(
      expand([row], '2026-10-01', '2026-11-10').map(x =>
        new Date(x.start).getUTCHours(),
      ),
    ).toEqual([7, 8, 8]);
  });
  it('supports monthly ordinal weekdays, interval, UTC UNTIL and exclusions/additions', () => {
    const row = series({
      recurrence: [
        'RRULE:FREQ=MONTHLY;BYDAY=1MO;INTERVAL=2;UNTIL=20260706T070000Z',
        'EXDATE:20260504T070000Z',
        'RDATE;TZID=Europe/Amsterdam:20260512T090000',
      ],
    });
    expect(expand([row], '2026-04-01', '2026-08-01').map(x => x.day)).toEqual([
      '2026-05-12',
      '2026-07-06',
    ]);
  });
  it('replaces moved instances by original instant and hides cancellations', () => {
    const moved = series({
      id: 'moved',
      recurrence: undefined,
      recurringEventId: 'weekly',
      originalStartTime: { dateTime: '2026-03-29T07:00:00Z' },
      start: { dateTime: '2026-04-02T11:00:00+02:00' },
      end: { dateTime: '2026-04-02T12:00:00+02:00' },
    });
    moved.subject = 'moved-row';
    const cancelled = series({
      id: 'cancelled',
      status: 'cancelled',
      recurrence: undefined,
      start: undefined,
      end: undefined,
      recurringEventId: 'weekly',
      originalStartTime: { dateTime: '2026-04-05T09:00:00+02:00' },
    });
    expect(
      expand([series(), moved, cancelled]).map(x => [x.day, x.subject]),
    ).toEqual([
      ['2026-03-22', 'series-row'],
      ['2026-04-02', 'moved-row'],
    ]);
  });
  it('suppresses the original even if the replacement moved outside the visible range', () => {
    const moved = series({
      id: 'moved',
      recurrence: undefined,
      recurringEventId: 'weekly',
      originalStartTime: { dateTime: '2026-03-29T07:00:00Z' },
      start: { dateTime: '2026-06-02T11:00:00+02:00' },
      end: { dateTime: '2026-06-02T12:00:00+02:00' },
    });
    expect(expand([series(), moved]).map(x => x.day)).toEqual([
      '2026-03-22',
      '2026-04-05',
    ]);
  });
  it('keeps calendars separate and deduplicates provider-expanded instances', () => {
    const instance = series({
      id: 'instance',
      recurrence: undefined,
      recurringEventId: 'weekly',
      originalStartTime: { dateTime: '2026-03-22T08:00:00Z' },
    });
    instance.subject = 'instance-row';
    const other = { ...series(), calendarId: 'personal', subject: 'other-row' };
    expect(expand([series(), instance, other])).toHaveLength(6);
    expect(expand([series(), instance])[0].subject).toBe('instance-row');
  });
  it('skips nonexistent local times without spending COUNT and chooses the earlier fold', () => {
    const row = series({
      start: {
        dateTime: '2026-03-22T02:30:00+01:00',
        timeZone: 'Europe/Amsterdam',
      },
      end: { dateTime: '2026-03-22T03:30:00+01:00' },
    });
    expect(expand([row]).map(x => x.day)).toEqual([
      '2026-03-22',
      '2026-04-05',
      '2026-04-12',
    ]);
  });
  it('rejects unsupported rules and malformed payloads explicitly', () => {
    expect(() =>
      expand([series({ recurrence: ['RRULE:FREQ=SECONDLY'] })]),
    ).toThrow(/frequency/i);
    expect(() =>
      expand([series({ start: { dateTime: '2026-03-22T09:00:00+01:00' } })]),
    ).toThrow(/zone/i);
    expect(() =>
      validateCalendarEvent({ id: 'x', start: { date: '2026-03-01' } }),
    ).toThrow(/all-day/i);
  });
});

it('expands civil-date series and preserves exclusive multi-day ends across DST', () => {
  const row = series({
    start: { date: '2026-03-27' },
    end: { date: '2026-03-30' },
    recurrence: ['RRULE:FREQ=WEEKLY;COUNT=3', 'EXDATE;VALUE=DATE:20260403'],
  });
  const result = expand([row], '2026-03-28', '2026-04-15');
  expect(result.map(x => [x.day, x.endDay, x.allDay])).toEqual([
    ['2026-03-27', '2026-03-30', true],
    ['2026-04-10', '2026-04-13', true],
  ]);
});
it('matches all-day cancelled exceptions by original civil date', () => {
  const row = series({
    start: { date: '2026-03-27' },
    end: { date: '2026-03-28' },
    recurrence: ['RRULE:FREQ=WEEKLY;UNTIL=20260410'],
  });
  const cancelled = series({
    id: 'cancelled',
    recurrence: undefined,
    status: 'cancelled',
    start: undefined,
    end: undefined,
    recurringEventId: 'weekly',
    originalStartTime: { date: '2026-04-03' },
  });
  expect(expand([row, cancelled]).map(x => x.day)).toEqual([
    '2026-03-27',
    '2026-04-10',
  ]);
});

it('supports yearly leap-day rules, set positions and unions without duplicates', () => {
  const row = series({
    start: { dateTime: '2024-02-29T09:00:00Z', timeZone: 'UTC' },
    end: { dateTime: '2024-02-29T10:00:00Z' },
    recurrence: ['RRULE:FREQ=YEARLY;COUNT=2;BYMONTH=2;BYMONTHDAY=29'],
  });
  expect(expand([row], '2025-01-01', '2026-01-01')).toEqual([]);
  expect(expand([row], '2028-01-01', '2029-01-01').map(x => x.day)).toEqual([
    '2028-02-29',
  ]);
  row.event.recurrence = [
    'RRULE:FREQ=MONTHLY;BYDAY=MO,TU,WE,TH,FR;BYSETPOS=-1;COUNT=3',
    'RDATE:20240329T090000Z',
  ];
  expect(expand([row], '2024-03-01', '2024-05-01').map(x => x.day)).toEqual([
    '2024-03-29',
    '2024-04-30',
  ]);
});
it('honors the explicit initial fold offset, then chooses the first generated fold', () => {
  const row = series({
    start: {
      dateTime: '2026-10-25T02:30:00+01:00',
      timeZone: 'Europe/Amsterdam',
    },
    end: { dateTime: '2026-10-25T03:30:00+01:00' },
    recurrence: ['RRULE:FREQ=WEEKLY;COUNT=1'],
  });
  expect(expand([row], '2026-10-01', '2026-11-01')[0].start).toBe(
    Date.parse('2026-10-25T01:30:00Z'),
  );
  row.event.start = {
    dateTime: '2026-10-18T02:30:00+02:00',
    timeZone: 'Europe/Amsterdam',
  };
  row.event.end = { dateTime: '2026-10-18T03:30:00+02:00' };
  row.event.recurrence = ['RRULE:FREQ=WEEKLY;COUNT=2'];
  expect(expand([row], '2026-10-01', '2026-11-01')[1].start).toBe(
    Date.parse('2026-10-25T00:30:00Z'),
  );
});
it('enforces exclusive query ends, interval and cancellation of entire series', () => {
  const row = series({ recurrence: ['RRULE:FREQ=DAILY;INTERVAL=2;COUNT=3'] });
  expect(
    expand([row], '2026-03-22T08:00:00Z', '2026-03-26T08:00:00Z').map(
      x => x.day,
    ),
  ).toEqual(['2026-03-22', '2026-03-24']);
  row.event.status = 'cancelled';
  expect(expand([row])).toEqual([]);
});
it.each([
  'FREQ=DAILY;COUNT=2garbage',
  'FREQ=DAILY;INTERVAL=0',
  'FREQ=WEEKLY;BYDAY=1MO',
  'FREQ=MONTHLY;BYMONTHDAY=0',
  'FREQ=MONTHLY;BYSETPOS=1',
  'FREQ=DAILY;COUNT=2;COUNT=3',
])('refuses malformed rule %s', rule => {
  expect(() => expand([series({ recurrence: [`RRULE:${rule}`] })])).toThrow();
});
