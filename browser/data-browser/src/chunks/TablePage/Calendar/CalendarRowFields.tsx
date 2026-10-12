import {
  anchorOf,
  buildRecurrence,
  isCalendarInstant,
  viewerTimeZone,
  nativeCalendarPayload,
  parseRecurrence,
  type RepeatParse,
} from '@tomic/lib/calendar-recurrence.js';
import { JSONValue, Resource, useCanWrite, useResource } from '@tomic/react';
import { useState, type JSX } from 'react';
import toast from 'react-hot-toast';
import { styled } from 'styled-components';
import { ValueForm } from '@components/forms/ValueForm';
import {
  calendarRowTime,
  isNativePayload,
  daysSpanned,
  endDayFor,
  localTimeInput,
  readRecurrencePayload,
  rowRecord,
  timedValue,
  valueToDayKey,
  type CalendarColumns,
  type RecurrencePayload,
} from './calendarRows';
import { RepeatField } from './RepeatField';
import { EventTimeFields, type EventTimeChange } from './EventTimeFields';

/** What the row dialog needs to show a calendar row's own fields. */
export interface CalendarRowContext extends CalendarColumns {
  ensureRecurrenceProp: () => Promise<string>;
  ensureTimeProps: () => Promise<{ start: string; end: string }>;
  /** Only the Repeat field, no time of day: the table view's row dialog,
   * where Start and End are columns of their own. */
  repeatOnly?: boolean;
}

/** The calendar fields of a row in its dialog: its time of day (#1802) and
 * how it repeats (#1801). */
export function CalendarRowFields({
  subject,
  calendar,
}: {
  subject: string;
  calendar: CalendarRowContext;
}): JSX.Element | null {
  const resource = useResource(subject);
  const canWrite = useCanWrite(resource);
  const [saving, setSaving] = useState(false);
  const { recurrenceProp } = calendar;

  const get = (prop: string) => resource.get(prop);
  const { payload, time, anchor, parsed } = readRowRepeat(
    subject,
    get,
    calendar,
  );

  if (!anchor) {
    // Without a day there is nothing to repeat from.
    return null;
  }

  const save = (next: RepeatParse) => {
    if (next.kind === 'custom') return;
    setSaving(true);
    void saveRepeat(
      resource,
      calendar,
      nextPayload(subject, next, payload, time),
    )
      .catch(error =>
        toast.error(`Could not save the repeat: ${errorMessage(error)}`),
      )
      .then(() => setSaving(false));
  };

  const saveTime = (next: EventTimeChange) => {
    setSaving(true);
    void saveTimes(resource, calendar, next)
      .catch(error =>
        toast.error(`Could not save the time: ${errorMessage(error)}`),
      )
      .then(() => setSaving(false));
  };

  // An imported series keeps the provider's times.
  const imported = !!payload && !isNativePayload(payload);
  const zone = viewerTimeZone();
  const endValue = calendar.endProp && get(calendar.endProp.subject);
  const startTime = time?.timed
    ? localTimeInput(time.start.dateTime!, zone)
    : undefined;
  const endTime =
    time?.timed && isCalendarInstant(endValue)
      ? localTimeInput(time.end.dateTime!, zone)
      : undefined;

  return (
    <Section>
      {!imported && !calendar.repeatOnly && (
        <EventTimeFields
          key={`${subject}:${startTime}:${endTime}`}
          allDay={!time?.timed}
          start={startTime}
          end={endTime}
          disabled={!canWrite || saving}
          onChange={saveTime}
        />
      )}
      <RepeatField
        parsed={parsed}
        anchor={anchor}
        disabled={!canWrite || saving}
        onChange={save}
        json={
          recurrenceProp && (
            <ValueForm
              resource={resource}
              propertyURL={recurrenceProp.subject}
            />
          )
        }
      />
    </Section>
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** The row's series as the Repeat field shows it. An imported series repeats
 * from its own start; a native one from the row's day. Without an `anchor`
 * the row has nothing to repeat from, and no Repeat field. */
export function readRowRepeat(
  subject: string,
  get: (prop: string) => unknown,
  calendar: CalendarRowContext,
) {
  const { recurrenceProp } = calendar;
  const value = recurrenceProp ? get(recurrenceProp.subject) : undefined;
  const payload = readRecurrencePayload(value);
  const time = calendarRowTime(
    get,
    calendar,
    undefined,
    payload && isNativePayload(payload)
      ? payload.event.start?.timeZone
      : undefined,
  );

  try {
    // A native series as the view expands it: moved along with its row.
    const event =
      payload && time && isNativePayload(payload)
        ? rowRecord(subject, payload, time).event
        : payload?.event;
    const start =
      payload && !isNativePayload(payload) ? event?.start : time?.start;
    const anchor = start && anchorOf(start);
    const parsed: RepeatParse =
      event && anchor
        ? parseRecurrence(event.recurrence, anchor)
        : value !== undefined
          ? { kind: 'custom' }
          : { kind: 'none' };

    return { payload, time, anchor, parsed };
  } catch {
    return {
      payload,
      time,
      anchor: time && anchorOf(time.start),
      parsed: { kind: 'custom' } as RepeatParse,
    };
  }
}

/** Stores a row's times, or makes it all day again. The date stays the
 * row's Day. An event that spans several days keeps its length in days; a
 * same-day one whose end is at or before the start ends the next day. */
async function saveTimes(
  resource: Resource,
  calendar: CalendarRowContext,
  next: EventTimeChange,
) {
  const { allDayProp, dateProp } = calendar;

  if (next === 'all-day') {
    for (const prop of [calendar.startProp, calendar.endProp]) {
      if (prop) resource.remove(prop.subject);
    }

    if (allDayProp) await resource.set(allDayProp.subject, true);
    await resource.save();

    return;
  }

  const day = valueToDayKey(resource.get(dateProp.subject), dateProp.datatype);
  if (!day) throw new Error('The event has no date');
  const zone = viewerTimeZone();
  // Read before `ensureTimeProps`/`set` touch it: a multi-day event keeps the
  // date its end is on, whatever time of day is edited.
  const previousEnd = calendar.endProp
    ? resource.get(calendar.endProp.subject)
    : undefined;
  const props = await calendar.ensureTimeProps();
  await resource.set(props.start, timedValue(day, next.start, zone));

  if (next.end) {
    const endDay = endDayFor(
      day,
      daysSpanned(day, previousEnd),
      next.start,
      next.end,
    );
    await resource.set(props.end, timedValue(endDay, next.end, zone));
  } else {
    resource.remove(props.end);
  }

  if (allDayProp) await resource.set(allDayProp.subject, false);
  await resource.save();
}

async function saveRepeat(
  resource: Resource,
  calendar: CalendarRowContext,
  value: RecurrencePayload | undefined,
) {
  const property = await calendar.ensureRecurrenceProp();

  // `set` validates, and undefined is not a JSON value.
  if (value === undefined) {
    resource.remove(property);
  } else {
    await resource.set(property, value as JSONValue);
  }

  await resource.save();
}

/** The value to store for a new Repeat setting. A native series is written
 * whole; an imported one keeps its payload and only gets new rule lines.
 * "Does not repeat" clears a native series and ends an imported one's rule. */
function nextPayload(
  subject: string,
  next: Exclude<RepeatParse, { kind: 'custom' }>,
  payload: RecurrencePayload | undefined,
  time: ReturnType<typeof calendarRowTime>,
): RecurrencePayload | undefined {
  if (payload && !isNativePayload(payload)) {
    const { recurrence: _, ...event } = payload.event;

    return next.kind === 'none'
      ? { ...payload, event }
      : {
          ...payload,
          event: {
            ...event,
            recurrence: buildRecurrence(next.rule, anchorOf(event.start!)),
          },
        };
  }

  if (next.kind === 'none' || !time) return undefined;

  return nativeCalendarPayload(subject, next.rule, time);
}

const Section = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  padding: 0.5rem;
  margin-bottom: 1rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
`;
