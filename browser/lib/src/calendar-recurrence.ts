/** Provider payloads remain authoritative. rrule dates encode floating wall time
 * as UTC; Temporal alone converts to instants, independent of the host zone. */
import { Temporal } from '@js-temporal/polyfill';
import { RRule } from 'rrule';
import { isCalendarDate } from './calendar-date.js';

export interface CalendarTime {
  dateTime?: string;
  timeZone?: string;
  date?: string;
}
export interface CalendarEvent {
  id: string;
  summary?: string;
  status?: string;
  start?: CalendarTime;
  end?: CalendarTime;
  recurrence?: string[];
  recurringEventId?: string;
  originalStartTime?: CalendarTime;
  [key: string]: unknown;
}
export interface CalendarRecord {
  calendarId: string;
  subject: string;
  event: CalendarEvent;
}
export interface CalendarOccurrence {
  key: string;
  subject: string;
  start: number;
  end: number;
  day: string;
  endDay: string;
  allDay: boolean;
  recurring: boolean;
}
export const calendarRecurrenceShortname = 'atomic-calendar-recurrence';
const MAX_STEPS = 100000;

function instant(time: CalendarTime | undefined): number {
  if (isCalendarDate(time?.date)) return Date.parse(`${time.date}T00:00:00Z`);
  if (!time?.dateTime) throw new Error('Timed event needs a dateTime');

  return Temporal.Instant.from(time.dateTime).epochMilliseconds;
}

function wallAt(ms: number, zone: string) {
  return Temporal.Instant.fromEpochMilliseconds(ms)
    .toZonedDateTimeISO(zone)
    .toPlainDateTime();
}

function floating(wall: Temporal.PlainDateTime): Date {
  return new Date(`${wall.toString({ smallestUnit: 'second' })}Z`);
}

/** RFC 5545: skip generated nonexistent times; take the first repeated time. */
function wallInstant(
  wall: Temporal.PlainDateTime,
  zone: string,
): number | undefined {
  const zoned = wall.toZonedDateTime(zone, { disambiguation: 'compatible' });

  return zoned.toPlainDateTime().equals(wall)
    ? zoned.epochMilliseconds
    : undefined;
}

function recurrenceZone(event: CalendarEvent): string {
  if (event.start?.date) return 'UTC';
  const zone = event.start?.timeZone;
  if (!zone || /^[+-]/.test(zone))
    throw new Error('Recurring timed events require an IANA time zone');
  wallAt(0, zone);

  return zone;
}

function eventDay(
  event: CalendarEvent,
  ms: number,
  fallbackZone?: string,
): string {
  if (event.start?.date) return new Date(ms).toISOString().slice(0, 10);
  const zone = event.start?.timeZone ?? fallbackZone;

  return zone
    ? wallAt(ms, zone).toPlainDate().toString()
    : event.start!.dateTime!.slice(0, 10);
}

function dateList(line: string, zone: string, allDay = false): number[] {
  if (allDay) {
    const match = /^(?:EXDATE|RDATE);VALUE=DATE:(.+)$/.exec(line);
    if (!match) throw new Error('All-day recurrence dates require VALUE=DATE');

    return match[1].split(',').map(value => {
      if (!/^\d{8}$/.test(value)) throw new Error('Invalid recurrence date');
      const date = `${value.slice(0, 4)}-${value.slice(4, 6)}-${value.slice(6)}`;
      if (!isCalendarDate(date)) throw new Error('Invalid recurrence date');

      return instant({ date });
    });
  }

  const match = /^(?:EXDATE|RDATE)(?:;TZID=([^:;]+))?:(.+)$/.exec(line);
  if (!match) throw new Error(`Unsupported recurrence date: ${line}`);

  return match[2].split(',').map(value => {
    const parts = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})(Z)?$/.exec(
      value,
    );
    if (!parts) throw new Error(`Invalid recurrence date: ${value}`);
    const iso = `${parts[1]}-${parts[2]}-${parts[3]}T${parts[4]}:${parts[5]}:${parts[6]}`;
    if (parts[7]) return Temporal.Instant.from(`${iso}Z`).epochMilliseconds;
    const result = wallInstant(
      Temporal.PlainDateTime.from(iso),
      match[1] ?? zone,
    );
    if (result === undefined)
      throw new Error(`Nonexistent recurrence date: ${value}`);

    return result;
  });
}

function parseRule(line: string, allDay = false) {
  const keys = line
    .slice(6)
    .split(';')
    .map(part => part.split('=')[0]);
  if (new Set(keys).size !== keys.length)
    throw new Error('Duplicate recurrence rule part');
  const allowed = new Set([
    'FREQ',
    'INTERVAL',
    'COUNT',
    'UNTIL',
    'BYDAY',
    'BYMONTHDAY',
    'BYMONTH',
    'BYSETPOS',
    'WKST',
  ]);
  if (keys.some(key => !allowed.has(key)))
    throw new Error('Unsupported recurrence rule part');

  for (const part of line.slice(6).split(';')) {
    const [key, value] = part.split('=');
    if (!value || part.split('=').length !== 2)
      throw new Error('Invalid recurrence rule part');
    if (
      ['INTERVAL', 'COUNT', 'BYMONTHDAY', 'BYMONTH', 'BYSETPOS'].includes(
        key,
      ) &&
      !/^[+-]?\d+(,[+-]?\d+)*$/.test(value)
    )
      throw new Error('Invalid recurrence number');
    if (['INTERVAL', 'COUNT'].includes(key) && value.includes(','))
      throw new Error('Invalid recurrence number');
    if (
      key === 'BYDAY' &&
      value
        .split(',')
        .some(day => !/^([+-]?[1-9]\d?)?(MO|TU|WE|TH|FR|SA|SU)$/.test(day))
    )
      throw new Error('Invalid recurrence weekday');
  }

  const options = RRule.parseString(line);
  if (options.freq === undefined || options.freq > RRule.DAILY)
    throw new Error(
      'Unsupported recurrence frequency (use daily, weekly, monthly or yearly)',
    );
  if (
    options.interval !== undefined &&
    (!Number.isSafeInteger(options.interval) ||
      options.interval < 1 ||
      options.interval > 1000)
  )
    throw new Error('Invalid recurrence interval');
  if (
    options.count !== undefined &&
    options.count !== null &&
    (!Number.isSafeInteger(options.count) ||
      options.count < 1 ||
      options.count > MAX_STEPS)
  )
    throw new Error('Invalid recurrence count');
  if (options.count && options.until)
    throw new Error('Use COUNT or UNTIL, not both');
  if (
    options.until &&
    !(allDay ? /;UNTIL=\d{8}(?:;|$)/ : /;UNTIL=\d{8}T\d{6}Z(?:;|$)/).test(line)
  )
    throw new Error(
      'Recurrence UNTIL must match the start type (UTC for timed events)',
    );
  if (options.freq === RRule.WEEKLY && options.bymonthday)
    throw new Error('Weekly rules cannot use BYMONTHDAY');
  const byday = /(?:^|;)BYDAY=([^;]+)/.exec(line.slice(6))?.[1];
  if (
    byday?.split(',').some(day => /\d/.test(day)) &&
    options.freq !== RRule.MONTHLY &&
    options.freq !== RRule.YEARLY
  )
    throw new Error('Ordinal weekdays require monthly or yearly frequency');
  if (
    byday
      ?.split(',')
      .some(day => /\d/.test(day) && Math.abs(parseInt(day)) > 53)
  )
    throw new Error('Invalid weekday ordinal');
  if (
    options.bysetpos &&
    !keys.some(key => ['BYDAY', 'BYMONTHDAY', 'BYMONTH'].includes(key))
  )
    throw new Error('BYSETPOS requires another BY part');

  const check = (
    values: number | number[] | null | undefined,
    min: number,
    max: number,
    noZero = false,
  ) => {
    if (values === undefined || values === null) return;
    for (const value of Array.isArray(values) ? values : [values])
      if (
        !Number.isInteger(value) ||
        value < min ||
        value > max ||
        (noZero && value === 0)
      )
        throw new Error('Invalid recurrence BY value');
  };

  check(options.bymonth, 1, 12);
  check(options.bymonthday, -31, 31, true);
  check(options.bysetpos, -366, 366, true);

  return options;
}

/** Validate before saving any records. Unsupported formats fail explicitly. */
export function validateCalendarEvent(event: CalendarEvent): void {
  if (!event || typeof event.id !== 'string' || !event.id)
    throw new Error('Calendar event needs an id');
  if (event.originalStartTime) instant(event.originalStartTime);
  if (event.recurringEventId && !event.originalStartTime)
    throw new Error('Recurring instance needs originalStartTime');
  if (event.status === 'cancelled') return;
  const allDay = event.start?.date !== undefined;
  if (
    allDay &&
    (!isCalendarDate(event.start?.date) || !isCalendarDate(event.end?.date))
  )
    throw new Error('Invalid all-day event range');
  if (allDay !== (event.end?.date !== undefined))
    throw new Error('Mixed calendar start/end types');
  const start = instant(event.start),
    end = instant(event.end);
  if (end <= start) throw new Error('Event end must be after its start');

  if (event.recurrence !== undefined) {
    if (!Array.isArray(event.recurrence) || event.recurrence.length > 16)
      throw new Error('Invalid or excessive recurrence lines');
    const zone = recurrenceZone(event);

    for (const line of event.recurrence) {
      if (typeof line !== 'string' || line.length > 2048)
        throw new Error('Invalid recurrence line');
      if (line.startsWith('RRULE:')) parseRule(line, allDay);
      else dateList(line, zone, allDay);
    }
  }
}
/** Expand [from,to), retaining original-instance identity even after a move.
 * Pass the complete imported calendar: exceptions can move out of the window.
 * Cancelled records are tombstones, never ordinary meetings. */
export function expandCalendar(
  records: CalendarRecord[],
  from: number,
  to: number,
): CalendarOccurrence[] {
  if (
    !Number.isFinite(from) ||
    !Number.isFinite(to) ||
    from >= to ||
    to - from > 366 * 86400000
  )
    throw new Error('Calendar expansion needs a window of at most one year');
  if (records.length > 5000) throw new Error('Too many calendar records');
  const identity = (calendar: string, id: string) =>
    JSON.stringify([calendar, id]);
  const masters = new Map<string, CalendarRecord>(),
    overrides = new Set<string>();

  for (const record of records) {
    if (
      typeof record.calendarId !== 'string' ||
      !record.calendarId ||
      typeof record.subject !== 'string' ||
      !record.subject
    )
      throw new Error('Calendar record needs source identity and subject');
    validateCalendarEvent(record.event);
    const key = identity(record.calendarId, record.event.id);
    if (masters.has(key)) throw new Error('Duplicate calendar event identity');
    masters.set(key, record);

    if (record.event.recurringEventId) {
      const instanceKey = JSON.stringify([
        record.calendarId,
        record.event.recurringEventId,
        instant(record.event.originalStartTime),
      ]);
      if (overrides.has(instanceKey))
        throw new Error('Duplicate recurring instance');
      overrides.add(instanceKey);
    }
  }

  const output: CalendarOccurrence[] = [];
  let steps = 0;

  for (const { calendarId, subject, event } of records) {
    if (event.status === 'cancelled') continue;
    const master = event.recurringEventId
      ? masters.get(identity(calendarId, event.recurringEventId))?.event
      : undefined;
    if (master?.status === 'cancelled') continue;
    const start = instant(event.start),
      duration = instant(event.end) - start;

    const emit = (ms: number) => {
      if ((event.start?.date ? ms + duration <= from : ms < from) || ms >= to)
        return;
      const key = JSON.stringify([
        calendarId,
        event.recurringEventId ?? event.id,
        event.recurringEventId ? instant(event.originalStartTime) : ms,
      ]);
      if (!event.recurringEventId && overrides.has(key)) return;
      output.push({
        key,
        subject,
        start: ms,
        end: ms + duration,
        day: eventDay(event, ms, master?.start?.timeZone),
        endDay: eventDay(event, ms + duration, master?.start?.timeZone),
        allDay: !!event.start?.date,
        recurring: !!event.recurrence?.length || !!event.recurringEventId,
      });
      if (output.length > 10000)
        throw new Error('Too many occurrences in this calendar window');
    };

    if (!event.recurrence?.length) {
      emit(start);
      continue;
    }

    const zone = recurrenceZone(event),
      wall = wallAt(start, zone);
    const wallEnd = floating(wallAt(to, zone).add({ days: 1 }));
    if (wall.year < 1900 || wallEnd.getUTCFullYear() - wall.year > 200)
      throw new Error('Recurring series exceeds the 200-year expansion limit');
    const included = new Set<number>(),
      excluded = new Set<number>();

    for (const line of event.recurrence) {
      if (!line.startsWith('RRULE:')) {
        dateList(line, zone, !!event.start?.date).forEach(ms =>
          (line.startsWith('EXDATE') ? excluded : included).add(ms),
        );
        continue;
      }

      const { count, until, ...options } = parseRule(line, !!event.start?.date);
      let valid = 0;
      // Apply COUNT after dropping nonexistent wall times; UNTIL is an instant.
      new RRule(
        { ...options, dtstart: floating(wall), until: wallEnd },
        true,
      ).all(date => {
        if (++steps > MAX_STEPS)
          throw new Error('Recurrence expansion exceeded its work limit');
        const ms =
          date.getTime() === floating(wall).getTime()
            ? start
            : wallInstant(
                Temporal.PlainDateTime.from(date.toISOString().slice(0, -1)),
                zone,
              );
        if (ms === undefined) return true;
        if ((until && ms > until.getTime()) || (count && valid >= count))
          return false;
        valid++;
        if ((event.start?.date ? ms + duration > from : ms >= from) && ms < to)
          included.add(ms);

        return true;
      });
    }

    for (const ms of included) if (!excluded.has(ms)) emit(ms);
  }

  return output.sort((a, b) => a.start - b.start || a.key.localeCompare(b.key));
}
