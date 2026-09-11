import {
  expandCalendar,
  isAllDayOnDate,
  type CalendarRecord,
  type CalendarOccurrence,
} from '@tomic/lib';

export { matchesCalendarField as calendarPropertyMatches } from '@tomic/lib';

export function calendarOccurrenceBuckets(
  records: CalendarRecord[],
  days: string[],
) {
  const buckets = new Map<string, CalendarOccurrence[]>();
  if (!days.length || !records.length) return buckets;
  // The view groups by the event's civil day, not the browser's timezone.
  // Include offset margins before assigning actual civil dates to cells.
  const from = Date.parse(`${days[0]}T00:00:00Z`) - 86400000;
  const to = Date.parse(`${days[days.length - 1]}T00:00:00Z`) + 2 * 86400000;

  for (const occurrence of expandCalendar(records, from, to)) {
    for (const day of days) {
      if (
        occurrence.allDay
          ? isAllDayOnDate(occurrence.day, occurrence.endDay, day)
          : occurrence.day === day
      ) {
        buckets.set(day, [...(buckets.get(day) ?? []), occurrence]);
      }
    }
  }

  return buckets;
}
