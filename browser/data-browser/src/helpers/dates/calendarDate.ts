import { isCalendarDate } from '@tomic/react';

/**
 * A `date` value (`YYYY-MM-DD`) is a civil date: it has no time and no zone.
 * `new Date('2026-10-02')` reads it as UTC midnight, which shows as 02:00 in
 * Amsterdam and as the day before in New York. Build local midnight of the
 * same day instead, so formatting it in the local zone gives back that day.
 *
 * Returns undefined for anything that is not a valid civil date.
 */
export function calendarDateToLocalDate(value: unknown): Date | undefined {
  if (!isCalendarDate(value)) {
    return undefined;
  }

  const [year, month, day] = value.split('-').map(Number);
  const date = new Date(year, month - 1, day);
  // Two-digit years would otherwise be mapped to 19xx.
  date.setFullYear(year);

  return date;
}

/**
 * The civil date of an instant in the local zone, as `YYYY-MM-DD`.
 * `toISOString().slice(0, 10)` gives the UTC day, which is still yesterday for
 * the first hours of a day in any zone ahead of UTC: a button that stamps
 * "today" then stored the day before.
 */
export function localCalendarDate(instant: Date = new Date()): string {
  const year = String(instant.getFullYear()).padStart(4, '0');
  const month = String(instant.getMonth() + 1).padStart(2, '0');
  const day = String(instant.getDate()).padStart(2, '0');

  return `${year}-${month}-${day}`;
}

/**
 * Formats a civil date without a time. Falls back to the raw value when it is
 * not a `YYYY-MM-DD` string, rather than guessing at an instant.
 */
export function formatCalendarDate(
  value: unknown,
  options?: Intl.DateTimeFormatOptions,
): string {
  const date = calendarDateToLocalDate(value);

  if (!date) {
    return String(value ?? '');
  }

  return date.toLocaleDateString(undefined, options);
}
