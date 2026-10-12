import { describe, expect, it } from 'vitest';
import {
  defaultRepeatRule,
  nativeCalendarPayload,
} from '@tomic/lib/calendar-recurrence.js';
import { Datatype } from '@tomic/lib';
import {
  allDayRowTime,
  calendarRowTime,
  daysSpanned,
  endDayFor,
  localTimeInput,
  readRecurrencePayload,
  rowRecord,
  timedValue,
} from './calendarRows';
import { calendarOccurrenceBuckets } from './calendarOccurrences';

const weekly = nativeCalendarPayload(
  'row',
  defaultRepeatRule('weekly', { date: '2026-10-01' }),
  allDayRowTime('2026-10-01'),
);

describe('rowRecord', () => {
  it('moves a native series with its row', () => {
    // Moved from Thursday 1 Oct to Friday 2 Oct in the table.
    const record = rowRecord('row', weekly, allDayRowTime('2026-10-02'));
    expect(record.event.recurrence).toEqual(['RRULE:FREQ=WEEKLY;BYDAY=FR']);
    const { buckets } = calendarOccurrenceBuckets(
      [record],
      ['2026-10-01', '2026-10-02', '2026-10-08', '2026-10-09'],
    );
    expect([...buckets.keys()]).toEqual(['2026-10-02', '2026-10-09']);
  });

  it('keeps a multi-day row multi-day', () => {
    const record = rowRecord(
      'row',
      weekly,
      allDayRowTime('2026-10-01', '2026-10-03'),
    );
    expect(record.event.end).toEqual({ date: '2026-10-03' });
  });

  it('leaves an imported payload as the provider wrote it', () => {
    const imported = {
      calendarId: 'work@example.com',
      event: {
        id: 'standup',
        start: { date: '2026-10-01' },
        end: { date: '2026-10-02' },
        recurrence: ['RRULE:FREQ=WEEKLY'],
      },
    };
    expect(rowRecord('row', imported, allDayRowTime('2026-10-05'))).toEqual({
      ...imported,
      subject: 'row',
    });
  });

  it('keeps a custom native rule as written', () => {
    const custom = {
      ...weekly,
      event: {
        ...weekly.event,
        recurrence: ['RRULE:FREQ=WEEKLY', 'EXDATE;VALUE=DATE:20261008'],
      },
    };
    expect(
      rowRecord('row', custom, allDayRowTime('2026-10-01')).event.recurrence,
    ).toEqual(custom.event.recurrence);
  });
});

describe('readRecurrencePayload', () => {
  it('reads objects and JSON-encoded strings, and nothing else', () => {
    expect(readRecurrencePayload(weekly)).toBe(weekly);
    expect(readRecurrencePayload(JSON.stringify(weekly))).toEqual(weekly);
    expect(readRecurrencePayload('{"weekly":true}')).toBeUndefined();
    expect(readRecurrencePayload(undefined)).toBeUndefined();
    expect(readRecurrencePayload(['RRULE:FREQ=DAILY'])).toBeUndefined();
  });
});

// #1802: times live in atomic-calendar-start / -end (RFC 3339 strings with
// their offset, per the Event ontology); Day and End day keep their meaning.
describe('calendarRowTime', () => {
  const columns = {
    dateProp: { subject: 'day', datatype: Datatype.DATE },
    allDayProp: { subject: 'allDay' },
    endDayProp: { subject: 'endDay' },
    startProp: { subject: 'start' },
    endProp: { subject: 'end' },
    calendarDate: true,
  };
  const row =
    (values: Record<string, unknown>) =>
    (prop: string): unknown =>
      values[prop];
  const AMS = 'Europe/Amsterdam';

  it('reads a timed row from its start and end', () => {
    expect(
      calendarRowTime(
        row({
          day: '2026-10-12',
          start: '2026-10-12T09:30:00+02:00',
          end: '2026-10-12T10:15:00+02:00',
        }),
        columns,
        AMS,
      ),
    ).toEqual({
      start: { dateTime: '2026-10-12T09:30:00+02:00', timeZone: AMS },
      end: { dateTime: '2026-10-12T10:15:00+02:00' },
      timed: true,
    });
  });

  it('keeps an all-day row date-only, with its exclusive end', () => {
    expect(
      calendarRowTime(
        row({
          day: '2026-11-16',
          endDay: '2026-11-19',
          allDay: true,
          start: '2026-11-16T09:30:00+01:00',
        }),
        columns,
        AMS,
      ),
    ).toEqual({
      start: { date: '2026-11-16' },
      end: { date: '2026-11-19' },
    });
  });

  it('takes the date from Day and the time from Start', () => {
    // Day moved in the table from the 12th to the 13th.
    const time = calendarRowTime(
      row({
        day: '2026-10-13',
        start: '2026-10-12T09:30:00+02:00',
        end: '2026-10-12T10:15:00+02:00',
      }),
      columns,
      AMS,
    );
    expect(time?.start.dateTime).toBe('2026-10-13T09:30:00+02:00');
    expect(time?.end.dateTime).toBe('2026-10-13T10:15:00+02:00');
  });

  it('gives a start without an end an hour, only to expand it', () => {
    const time = calendarRowTime(
      row({ day: '2026-10-12', start: '2026-10-12T09:30:00+02:00' }),
      columns,
      AMS,
    );
    expect(time?.end).toEqual({ dateTime: '2026-10-12T08:30:00.000Z' });
  });
});

describe('time inputs', () => {
  it('writes a local wall time with its offset, and reads it back', () => {
    const value = timedValue('2026-10-12', '09:30', 'Europe/Amsterdam');
    expect(value).toBe('2026-10-12T09:30:00+02:00');
    expect(localTimeInput(value, 'Europe/Amsterdam')).toBe('09:30');
    expect(localTimeInput(value, 'America/New_York')).toBe('03:30');
    expect(timedValue('2026-12-01', '09:30', 'Europe/Amsterdam')).toBe(
      '2026-12-01T09:30:00+01:00',
    );
  });
});

describe('multi-day timed events', () => {
  it('counts the days between the start day and the stored end', () => {
    expect(daysSpanned('2026-10-11', '2026-10-15T12:00:00+00:00')).toBe(4);
    expect(daysSpanned('2026-10-11', '2026-10-11T12:00:00+00:00')).toBe(0);
    expect(daysSpanned('2026-10-11', undefined)).toBe(0);
  });

  it('keeps a multi-day end on its day when only the time changes', () => {
    expect(endDayFor('2026-10-11', 4, '14:00', '11:01')).toBe('2026-10-15');
  });

  it('puts a same-day end at or before the start on the next day', () => {
    expect(endDayFor('2026-10-10', 0, '22:30', '06:45')).toBe('2026-10-11');
    expect(endDayFor('2026-10-10', 0, '09:00', '10:00')).toBe('2026-10-10');
  });
});
