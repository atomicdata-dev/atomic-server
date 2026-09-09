// @wc-ignore-file
import { Datatype } from '../../browser/lib/src/index.js';
import type { JSONValue } from '../../browser/lib/src/value.js';
import {
  isCalendarDate as validDay,
  calendarFields,
} from '../../browser/lib/src/calendar-date.js';
import type { FetchedPlatform, Term } from './schema.js';

export { calendarFields } from '../../browser/lib/src/calendar-date.js';

/** An additional projection, never a replacement for the provider's fields.
 * One DATE column supports both all-day dates and timed events in a single view.
 * Timed events use the date in Google's supplied offset; raw start/end retain
 * the instant and zone. All-day ends are also projected for range rendering.
 */
export function calendarProjection(fetched: FetchedPlatform): FetchedPlatform {
  if (fetched.platform !== 'google-calendar') return fetched;
  const event = fetched.ontology.terms.find(
    t => t.kind === 'class' && t.shortname === 'event',
  );
  if (!event) return fetched;
  const definitions: [string, Datatype, string][] = [
    [
      calendarFields.day,
      Datatype.DATE,
      "Start date in the event's supplied offset; all-day dates stay unchanged.",
    ],
    [
      calendarFields.endDay,
      Datatype.DATE,
      'Exclusive end of an all-day event; this date is not occupied.',
    ],
    [
      calendarFields.allDay,
      Datatype.BOOLEAN,
      'Whether Google represents this as an all-day event.',
    ],
    [
      calendarFields.notes,
      Datatype.STRING,
      'Display limitations and Google-only features. Edits here remain local.',
    ],
  ];
  const terms: Term[] = definitions.map(
    ([shortname, datatype, description]) => ({
      path: `urn:atomic:google-calendar:${shortname}`,
      kind: 'property',
      shortname,
      datatype,
      description,
      requires: [],
      recommends: [],
    }),
  );
  if (
    fetched.ontology.terms.some(t =>
      terms.some(extra => extra.shortname === t.shortname),
    )
  )
    throw new Error(
      'Calendar projection property collides with provider ontology',
    );
  return {
    ...fetched,
    ontology: {
      ...fetched.ontology,
      terms: [
        ...fetched.ontology.terms.map(t =>
          t === event
            ? {
                ...t,
                recommends: [
                  ...t.recommends,
                  ...terms.map(extra => extra.path),
                ],
              }
            : t,
        ),
        ...terms,
      ],
    },
    records: fetched.records.map(row => {
      if (row.resource !== 'event') return row;
      const start = object(row.values.start);
      const end = object(row.values.end);
      const date = start.date ?? start.dateTime;
      const cancelled = row.values.status === 'cancelled';
      if (
        !cancelled &&
        (typeof date !== 'string' || !validDay(date.slice(0, 10)))
      )
        throw new Error(`Calendar event ${row.id} has no valid start date`);
      if (
        start.date !== undefined &&
        (typeof start.date !== 'string' || !validDay(start.date))
      )
        throw new Error(`Calendar event ${row.id} has an invalid all-day date`);
      if (
        start.dateTime !== undefined &&
        (typeof start.dateTime !== 'string' ||
          !/^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/.test(start.dateTime) ||
          !Number.isFinite(Date.parse(start.dateTime)))
      )
        throw new Error(
          `Calendar event ${row.id} has no offset-qualified start time`,
        );
      const allDay = typeof start.date === 'string';
      if (
        !cancelled &&
        ((allDay &&
          (start.dateTime !== undefined ||
            end.dateTime !== undefined ||
            !validDay(end.date) ||
            end.date <= start.date!)) ||
          (!allDay && end.date !== undefined))
      )
        throw new Error(
          `Calendar event ${row.id} has an invalid all-day interval`,
        );
      const notes = [
        'Use Preview edits for Google to sync Name, Description, Location, Start and End',
      ];
      if (cancelled) notes.push('Cancelled in Google; retained in Atomic');
      if (
        row.values['recurring-event-id'] ||
        row.values.recurringEventId ||
        row.values.recurringeventid ||
        row.values.recurrence
      )
        notes.push('Recurring event: manage the series in Google');
      if (Array.isArray(row.values.attendees) && row.values.attendees.length)
        notes.push('Attendees and RSVP: manage in Google');
      if (row.values.reminders) notes.push('Reminders: manage in Google');
      if (
        row.values['conference-data'] ||
        row.values.conferenceData ||
        row.values.conferencedata
      )
        notes.push('Conferencing: manage in Google');
      if (!allDay && (end.date || end.dateTime))
        notes.push('Duration retained in End; shown on start day only');
      const values: Record<string, JSONValue> = {
        ...row.values,
        [calendarFields.notes]: notes.join('. '),
      };
      if (typeof date === 'string' && validDay(date.slice(0, 10))) {
        values[calendarFields.day] = date.slice(0, 10);
        values[calendarFields.allDay] = allDay;
        if (allDay && validDay(end.date))
          values[calendarFields.endDay] = end.date;
      }
      return { ...row, values };
    }),
  };
}
function object(value: JSONValue | undefined): Record<string, JSONValue> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value
    : {};
}
