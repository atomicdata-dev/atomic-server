export const calendarFields = {
  day: 'atomic-calendar-day',
  allDay: 'atomic-calendar-all-day',
  endDay: 'atomic-calendar-end-day',
  notes: 'atomic-calendar-notes',
};

/** A civil date, never an instant. Lexical order matches calendar order. */
export function isCalendarDate(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value))
    return false;
  const [year, month, day] = value.split('-').map(Number);
  if (year < 1 || month < 1 || month > 12 || day < 1) return false;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

  return day <= days[month - 1];
}

/** Google / RFC 5545 all-day ranges include start and exclude end.
 * Call once per visible day instead of expanding arbitrarily long events.
 */
export function isAllDayOnDate(
  start: unknown,
  end: unknown,
  day: string,
): boolean {
  return (
    isCalendarDate(start) &&
    isCalendarDate(end) &&
    isCalendarDate(day) &&
    start <= day &&
    day < end
  );
}

/** The next civil date, for the exclusive end of a newly created one-day event. */
export function nextCalendarDate(value: string): string {
  if (!isCalendarDate(value)) throw new Error('Invalid calendar date');
  let [year, month, day] = value.split('-').map(Number);
  const format = () =>
    `${String(year).padStart(4, '0')}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
  day += 1;

  if (!isCalendarDate(format())) {
    day = 1;
    month += 1;
  }

  if (month > 12) {
    month = 1;
    year += 1;
  }

  if (!isCalendarDate(format())) throw new Error('Calendar date out of range');

  return format();
}

/** Imported properties are namespaced by platformSchema; native ones are not. */
export function matchesCalendarField(
  actual: string | undefined,
  field: string,
): boolean {
  return actual === field || actual === `lt-google-calendar-property-${field}`;
}
