// @wc-ignore-file
import { Datatype } from '../../browser/lib/src/index.js';
import {
  calendarRecurrenceShortname,
  validateCalendarEvent,
  type CalendarEvent,
} from '../../browser/lib/src/calendar-recurrence.js';
import type { JSONValue } from '../../browser/lib/src/value.js';
import type { FetchedPlatform, Term } from './schema.js';

/** Additional projection: keep the provider's fields and retain an atomic
 * event payload so import reconciliation clears removed recurrence/exception
 * fields together instead of leaving stale optional columns behind. */
export function calendarRecurrenceProjection(
  fetched: FetchedPlatform,
): FetchedPlatform {
  if (fetched.platform !== 'google-calendar') return fetched;
  const eventClass = fetched.ontology.terms.find(
    t => t.kind === 'class' && t.shortname === 'event',
  );
  if (!eventClass) return fetched;
  const term: Term = {
    path: `urn:atomic:google-calendar:${calendarRecurrenceShortname}`,
    kind: 'property',
    shortname: calendarRecurrenceShortname,
    datatype: Datatype.JSON,
    description:
      'Timed calendar event and source calendar identity. Recurring chips open the series; changing this payload changes all its generated occurrences. Google remains unchanged.',
    requires: [],
    recommends: [],
  };
  if (fetched.ontology.terms.some(t => t.shortname === term.shortname))
    throw new Error(
      'Calendar recurrence property collides with provider ontology',
    );

  return {
    ...fetched,
    ontology: {
      ...fetched.ontology,
      terms: [
        ...fetched.ontology.terms.map(t =>
          t === eventClass
            ? { ...t, recommends: [...t.recommends, term.path] }
            : t,
        ),
        term,
      ],
    },
    records: fetched.records.map(row => {
      if (row.resource !== 'event') return row;
      const read = (key: string) =>
        row.values[key] ??
        row.values[
          key.replace(/[A-Z]/g, letter => `-${letter.toLowerCase()}`)
        ] ??
        row.values[key.toLowerCase()];
      const event: CalendarEvent = { id: row.id };

      for (const key of [
        'start',
        'end',
        'status',
        'recurrence',
        'recurringEventId',
        'originalStartTime',
      ]) {
        const value = read(key);
        if (value !== undefined && value !== null) event[key] = value;
      }

      // The civil-date adapter owns all-day rendering. An explicit empty
      // payload also clears a previous timed representation on reimport.
      if (
        (event.start?.date || event.originalStartTime?.date) &&
        !event.recurrence?.length &&
        !event.recurringEventId
      )
        return { ...row, values: { ...row.values, [term.shortname]: {} } };
      validateCalendarEvent(event);

      return {
        ...row,
        values: {
          ...row.values,
          [term.shortname]: {
            calendarId: row.namespace,
            event,
          } as unknown as JSONValue,
        },
      };
    }),
  };
}
