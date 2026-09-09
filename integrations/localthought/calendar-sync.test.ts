import { expect, it, vi } from 'vitest';
import {
  applyCalendarEdit,
  planCalendarEdit,
  previewCalendarEdits,
  eventPath,
} from './calendar-sync';
import {
  IMPORT_BASELINE,
  IMPORT_LOCAL_ID,
} from '../../browser/lib/src/import-records';
const name = 'https://atomicdata.dev/properties/name';
const config = {
  platform: 'google-calendar',
  destinations: { event: { table: 'table', rowClass: 'event' } },
  properties: {
    summary: 'summary',
    description: 'description',
    start: 'start',
    end: 'end',
  },
};
function fixture() {
  const prior = {
    [name]: 'Before',
    summary: 'Before',
    description: 'Notes',
    start: { date: '2026-09-10' },
    end: { date: '2026-09-11' },
  };
  const row = {
    ...prior,
    [name]: 'After',
    [IMPORT_LOCAL_ID]: JSON.stringify([
      'google-calendar',
      'event',
      'team@example.com',
      'id',
    ]),
    [IMPORT_BASELINE]: { values: prior, previous: {} },
    'https://atomicdata.dev/properties/parent': 'table',
    'https://atomicdata.dev/properties/isA': ['event'],
  };
  const remote = {
    ...prior,
    etag: '"1"',
    attendees: [{ email: 'guest@example.com' }],
  };
  return { row: row as Record<string, unknown>, remote };
}
it('sends a minimal title patch and checkpoints both imported title representations', async () => {
  const { row, remote } = fixture();
  const edit = planCalendarEdit('row', row, config, remote)!;
  expect(edit.patch).toEqual({ summary: 'After' });
  const request = vi.fn(async () => ({
    status: 200,
    body: JSON.stringify({ ...remote, summary: 'After' }),
  }));
  await applyCalendarEdit(
    edit,
    async () => row,
    request,
    async values => {
      Object.assign(row, values);
    },
  );
  expect(request).toHaveBeenCalledWith(
    '/calendar/v3/calendars/team%40example.com/events/id?sendUpdates=all',
    { method: 'PATCH', body: '{"summary":"After"}', ifMatch: '"1"' },
  );
  expect(row.summary).toBe('After');
  expect(
    planCalendarEdit('row', row, config, { ...remote, summary: 'After' }),
  ).toBeUndefined();
});
it('rejects conflicting local and remote edits without any writes', () => {
  const { row, remote } = fixture();
  expect(() =>
    planCalendarEdit('row', row, config, { ...remote, summary: 'Remote' }),
  ).toThrow('conflict');
  row.summary = 'Different';
  expect(() => planCalendarEdit('row', row, config, remote)).toThrow(
    'disagree',
  );
});
it('recovers a lost checkpoint without repeating a provider write', async () => {
  const { row, remote } = fixture();
  const edit = planCalendarEdit('row', row, config, {
    ...remote,
    summary: 'After',
  })!;
  const request = vi.fn();
  await applyCalendarEdit(
    edit,
    async () => row,
    request,
    async values => {
      Object.assign(row, values);
    },
  );
  expect(request).not.toHaveBeenCalled();
  expect(row.summary).toBe('After');
});
it('rejects stale local previews and remote ETags without checkpointing', async () => {
  const { row, remote } = fixture();
  const edit = planCalendarEdit('row', row, config, remote)!;
  const request = vi.fn(async () => ({ status: 412, body: '{}' }));
  const checkpoint = vi.fn();
  row[name] = 'New edit';
  await expect(
    applyCalendarEdit(edit, async () => row, request, checkpoint),
  ).rejects.toThrow('changed after preview');
  expect(request).not.toHaveBeenCalled();
  row[name] = 'After';
  await expect(
    applyCalendarEdit(edit, async () => row, request, checkpoint),
  ).rejects.toThrow('Google event changed');
  expect(checkpoint).not.toHaveBeenCalled();
});
it('preserves local edits made while a write is in flight', async () => {
  const { row, remote } = fixture();
  const edit = planCalendarEdit('row', row, config, remote)!;
  const checkpoint = vi.fn();
  await expect(
    applyCalendarEdit(
      edit,
      async () => row,
      async () => {
        row[name] = 'Newer';
        return {
          status: 200,
          body: JSON.stringify({ ...remote, summary: 'After' }),
        };
      },
      checkpoint,
    ),
  ).rejects.toThrow('changed after preview');
  expect(checkpoint).not.toHaveBeenCalled();
});
it('validates all-day dates, timed offsets and positive duration', () => {
  const { row, remote } = fixture();
  for (const start of [
    { date: '2026-02-30' },
    { date: '2026-09-12' },
    { dateTime: '2026-09-10T10:00:00' },
  ]) {
    row.start = start;
    expect(() => planCalendarEdit('row', row, config, remote)).toThrow();
  }
  row.start = {
    dateTime: '2026-09-10T10:00:00+02:00',
    timeZone: 'Europe/Amsterdam',
  };
  row.end = {
    dateTime: '2026-09-10T11:00:00+02:00',
    timeZone: 'Europe/Amsterdam',
  };
  expect(planCalendarEdit('row', row, config, remote)?.patch.start).toEqual(
    row.start,
  );
});
it('does not write unsupported fields, new rows or another destination', () => {
  const { row, remote } = fixture();
  row[name] = 'Before';
  row.attendees = [];
  row['atomic-calendar-day'] = '2026-09-12';
  expect(planCalendarEdit('row', row, config, remote)).toBeUndefined();
  delete row[IMPORT_LOCAL_ID];
  expect(eventPath(row, config)).toBeUndefined();
});
it('blocks duplicate identities before requesting provider data', async () => {
  const { row } = fixture();
  const request = vi.fn();
  await expect(
    previewCalendarEdits(
      new Map([
        ['a', row],
        ['b', row],
      ]),
      config,
      request,
    ),
  ).rejects.toThrow('Duplicate');
  expect(request).not.toHaveBeenCalled();
});
it('keeps credentials/errors out of the checkpoint on failed writes', async () => {
  const { row, remote } = fixture();
  const checkpoint = vi.fn();
  const edit = planCalendarEdit('row', row, config, remote)!;
  await expect(
    applyCalendarEdit(
      edit,
      async () => row,
      async () => ({ status: 403, body: 'secret' }),
      checkpoint,
    ),
  ).rejects.toThrow('write access');
  expect(checkpoint).not.toHaveBeenCalled();
});
