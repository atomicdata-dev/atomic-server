import { expect, it } from 'vitest';
import { calendarProjection, calendarFields as fields } from './calendar';
import { Datatype } from '../../browser/lib/src/index';
import { run } from './plugin';
import { platformSchema, type FetchedPlatform } from './schema';
import { matchesCalendarField } from '../../browser/lib/src/calendar-date';
const fixture = (): FetchedPlatform => ({
  platform: 'google-calendar',
  ontology: {
    description: '',
    terms: [
      {
        path: 'event',
        kind: 'class',
        shortname: 'event',
        description: '',
        datatype: Datatype.STRING,
        requires: [],
        recommends: [],
      },
    ],
  },
  records: [
    {
      resource: 'event',
      namespace: 'calendar-a',
      id: '1',
      name: 'Meeting',
      values: {
        start: {
          dateTime: '2026-09-10T00:30:00+02:00',
          timeZone: 'Europe/Amsterdam',
        },
        end: { dateTime: '2026-09-10T01:30:00+02:00' },
        attendees: [{ email: 'test@example.com' }],
        'recurring-event-id': 'series',
        reminders: { useDefault: true },
      },
    },
  ],
});
it('projects timed events without shifting their day and retains provider structures', () => {
  const input = fixture();
  const output = calendarProjection(input);
  expect(output.records[0].values).toMatchObject({
    ...input.records[0].values,
    [fields.day]: '2026-09-10',
    [fields.allDay]: false,
  });
  expect(output.records[0].values[fields.notes]).toContain('Recurring');
  expect(output.records[0].values[fields.notes]).toContain('Attendees');
  expect(input.records[0].values[fields.day]).toBeUndefined();
  expect(
    output.ontology.terms.find(t => t.shortname === fields.day)?.datatype,
  ).toBe(Datatype.DATE);
});
it('supports all-day dates and preserves exclusive multi-day ends', () => {
  const input = fixture();
  input.records[0].values = {
    start: { date: '2026-09-10' },
    end: { date: '2026-09-13' },
  };
  expect(calendarProjection(input).records[0].values).toMatchObject({
    [fields.day]: '2026-09-10',
    [fields.allDay]: true,
    end: { date: '2026-09-13' },
  });
});
it('retains cancelled events even when Google omits start', () => {
  const input = fixture();
  input.records[0].values = { status: 'cancelled' };
  expect(calendarProjection(input).records[0].values[fields.notes]).toContain(
    'Cancelled',
  );
});
it('fails the projection on malformed active events instead of silently losing rows', () => {
  for (const start of [
    { date: '2026-02-30' },
    { date: '2026-09-10garbage' },
    {},
    { dateTime: '2026-09-10T12:00:00' },
  ]) {
    const input = fixture();
    input.records[0].values = { start };
    expect(() => calendarProjection(input)).toThrow();
  }
});
it('leaves other platforms untouched', () => {
  const input = fixture();
  input.platform = 'pets';
  expect(calendarProjection(input)).toBe(input);
});
it("repeated imports reconcile IDs, preserve local fields and don't delete out-of-window events", () => {
  const data = calendarProjection(fixture());
  const properties = Object.fromEntries(
    Object.keys(data.records[0].values).map(k => [
      k,
      `https://example.com/${k}`,
    ]),
  );
  const config = {
    platform: data.platform,
    destinations: {
      event: { table: 'did:ad:table', rowClass: 'did:ad:event' },
    },
    properties,
    records: data.records,
  };
  const first = run({ config, query: () => [], read: () => ({}) }).intents[0];
  if (first.op !== 'create') throw new Error('Expected create');
  const saved = {
    ...first.set,
    'https://atomicdata.dev/properties/parent': 'did:ad:table',
    'https://atomicdata.dev/properties/isA': ['did:ad:event'],
    'https://example.com/private': 'my notes',
  };
  const host = {
    config,
    query: (p: string, v: string) => (saved[p] === v ? ['did:ad:row'] : []),
    read: () => saved,
  };
  expect(run(host).intents).toHaveLength(0);
  expect(
    run({ ...host, config: { ...config, records: [] } }).intents,
  ).toHaveLength(0);
  const changed = calendarProjection(fixture());
  changed.records[0].name = 'Updated meeting';
  const result = run({
    ...host,
    config: { ...config, records: changed.records },
  });
  expect(result.intents[0]).toMatchObject({
    op: 'set',
    subject: 'did:ad:row',
    set: { 'https://atomicdata.dev/properties/name': 'Updated meeting' },
  });
  expect(JSON.stringify(result.intents)).not.toContain('my notes');
  const secondCalendar = { ...data.records[0], namespace: 'calendar-b' };
  expect(
    run({ ...host, config: { ...config, records: [secondCalendar] } })
      .intents[0].op,
  ).toBe('create');
});
it('recognizes the lowercase field names produced by the WASM ontology', () => {
  const input = fixture();
  delete input.records[0].values['recurring-event-id'];
  input.records[0].values.recurringeventid = 'series';
  input.records[0].values.conferencedata = { conferenceId: 'meeting' };
  const notes = calendarProjection(input).records[0].values[fields.notes];
  expect(notes).toContain('Recurring event');
  expect(notes).toContain('Conferencing');
});

it('projects exclusive date-only ends and never fabricates timestamps', () => {
  const input = fixture();
  input.records[0].values = {
    start: { date: '2026-09-10' },
    end: { date: '2026-09-13' },
  };
  const values = calendarProjection(input).records[0].values;
  expect(values['atomic-calendar-end-day']).toBe('2026-09-13');
  expect(values.start).toEqual({ date: '2026-09-10' });
  expect(values.end).toEqual({ date: '2026-09-13' });
  expect(values[fields.notes]).not.toContain('shown on start day only');
});
it('rejects malformed or mixed all-day intervals instead of shortening them', () => {
  for (const end of [
    {},
    { date: '2026-02-30' },
    { date: '2026-09-10' },
    { date: '2026-09-09' },
    { dateTime: '2026-09-11T00:00:00Z' },
  ]) {
    const input = fixture();
    input.records[0].values = { start: { date: '2026-09-10' }, end };
    expect(() => calendarProjection(input)).toThrow();
  }
  const input = fixture();
  input.records[0].values.start = {
    date: '2026-09-10',
    dateTime: '2026-09-10T00:00:00Z',
  };
  expect(() => calendarProjection(input)).toThrow();
});

it('the installed schema exposes all-day range fields recognized by the view', () => {
  const projected = calendarProjection(fixture());
  const schema = platformSchema(projected.platform, projected.ontology.terms);
  for (const field of [fields.day, fields.allDay, fields.endDay]) {
    expect(
      schema.properties.filter(p => matchesCalendarField(p.shortname, field)),
    ).toHaveLength(1);
  }
});
