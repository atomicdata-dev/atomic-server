// @wc-ignore-file
import {
  IMPORT_BASELINE,
  IMPORT_LOCAL_ID,
} from '../../browser/lib/src/import-records.js';
import type { Config } from './plugin.js';

const NAME = 'https://atomicdata.dev/properties/name';
const PARENT = 'https://atomicdata.dev/properties/parent';
const IS_A = 'https://atomicdata.dev/properties/isA';
type Values = Record<string, unknown>;
export type CalendarRequest = (
  path: string,
  init?: {
    method?: string;
    body?: string;
    ifMatch?: string;
  },
) => Promise<{ status: number; body: string }>;
export interface CalendarEdit {
  subject: string;
  name: string;
  path: string;
  etag: string;
  patch: Values;
  observed: Values;
  acknowledged: Values;
}
export function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object')
    return `{${Object.entries(value)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, v]) => `${JSON.stringify(key)}:${canonical(v)}`)
      .join(',')}}`;
  return JSON.stringify(value) ?? 'undefined';
}
const same = (a: unknown, b: unknown) => canonical(a) === canonical(b);
function object(value: unknown): Values {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('Calendar sync needs a valid imported baseline');
  return value as Values;
}
export function eventPath(row: Values, config: Config): string | undefined {
  if (config.platform !== 'google-calendar') return;
  const target = config.destinations.event;
  if (
    !target ||
    row[PARENT] !== target.table ||
    !Array.isArray(row[IS_A]) ||
    !(row[IS_A] as unknown[]).includes(target.rowClass)
  )
    return;
  const raw = row[IMPORT_LOCAL_ID];
  if (typeof raw !== 'string') return;
  let id: unknown;
  try {
    id = JSON.parse(raw);
  } catch {
    return;
  }
  if (
    !Array.isArray(id) ||
    id.length !== 4 ||
    id[0] !== 'google-calendar' ||
    id[1] !== 'event' ||
    typeof id[2] !== 'string' ||
    !id[2] ||
    ['.', '..'].includes(id[2]) ||
    typeof id[3] !== 'string' ||
    !id[3] ||
    ['.', '..'].includes(id[3])
  )
    return;
  return `/calendar/v3/calendars/${encodeURIComponent(id[2])}/events/${encodeURIComponent(id[3])}`;
}
function validateTimes(start: unknown, end: unknown) {
  const a = object(start),
    b = object(end);
  const allDay = typeof a.date === 'string';
  const parse = (v: Values) => {
    if (allDay) {
      if (
        typeof v.date !== 'string' ||
        v.dateTime !== undefined ||
        !/^\d{4}-\d{2}-\d{2}$/.test(v.date)
      )
        throw new Error('Invalid all-day event dates');
      const time = Date.parse(`${v.date}T00:00:00Z`);
      if (
        !Number.isFinite(time) ||
        new Date(time).toISOString().slice(0, 10) !== v.date
      )
        throw new Error('Invalid all-day event dates');
      return time;
    }
    if (
      typeof v.dateTime !== 'string' ||
      v.date !== undefined ||
      !/^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/.test(v.dateTime) ||
      !Number.isFinite(Date.parse(v.dateTime))
    )
      throw new Error('Event times need an explicit UTC offset');
    return Date.parse(v.dateTime);
  };
  if (parse(b) <= parse(a)) throw new Error('Event end must follow its start');
}
/** Three-way merge only the supported provider fields; no full event replacement. */
export function planCalendarEdit(
  subject: string,
  row: Values,
  config: Config,
  remote: Values,
): CalendarEdit | undefined {
  const path = eventPath(row, config);
  if (!path) return;
  const baseline = object(object(row[IMPORT_BASELINE]).values);
  const patch: Values = {},
    observed: Values = {},
    acknowledged: Values = {};
  for (const field of ['summary', 'description', 'location', 'start', 'end']) {
    const properties =
      field === 'summary'
        ? [NAME, config.properties.summary].filter(Boolean)
        : [config.properties[field]].filter(Boolean);
    const changed = properties.filter(p => !same(row[p], baseline[p]));
    if (!changed.length) continue;
    const local = row[changed[0]] ?? '';
    if (changed.some(p => !same(row[p] ?? '', local)))
      throw new Error(
        'Title and Summary disagree; make them match before syncing',
      );
    if (
      ['summary', 'description', 'location'].includes(field) &&
      typeof local !== 'string'
    )
      throw new Error(`Calendar ${field} must be text`);
    if (
      !same(remote[field] ?? '', local) &&
      changed.some(p => !same(remote[field] ?? '', baseline[p] ?? ''))
    )
      throw new Error(
        `Calendar conflict in ${field}; fetch and resolve the source/local conflict first`,
      );
    for (const p of properties) {
      observed[p] = row[p];
      acknowledged[p] = local;
    }
    if (!same(remote[field] ?? '', local)) patch[field] = local;
  }
  if (!Object.keys(acknowledged).length) return;
  if (remote.status === 'cancelled')
    throw new Error('This event was cancelled in Google');
  if (patch.start || patch.end)
    validateTimes(patch.start ?? remote.start, patch.end ?? remote.end);
  if (typeof remote.etag !== 'string' || !remote.etag)
    throw new Error('Google did not return an event ETag');
  observed[IMPORT_LOCAL_ID] = row[IMPORT_LOCAL_ID];
  observed[IMPORT_BASELINE] = row[IMPORT_BASELINE];
  observed[PARENT] = row[PARENT];
  observed[IS_A] = row[IS_A];
  return {
    subject,
    name: String(row[NAME] ?? 'Event'),
    path,
    etag: remote.etag,
    patch: structuredClone(patch),
    observed: structuredClone(observed),
    acknowledged: structuredClone(acknowledged),
  };
}
export async function previewCalendarEdits(
  rows: Map<string, Values>,
  config: Config,
  request: CalendarRequest,
) {
  const edits: CalendarEdit[] = [];
  const identities = new Set<string>();
  for (const row of rows.values()) {
    const path = eventPath(row, config);
    if (path && identities.has(path))
      throw new Error(
        'Duplicate Calendar identity; resolve duplicate records before syncing',
      );
    if (path) identities.add(path);
  }
  for (const [subject, row] of rows) {
    const path = eventPath(row, config);
    if (!path) continue;
    const baseline = object(object(row[IMPORT_BASELINE]).values);
    if (
      ![
        NAME,
        ...['summary', 'description', 'location', 'start', 'end']
          .map(f => config.properties[f])
          .filter(Boolean),
      ].some(p => !same(row[p], baseline[p]))
    )
      continue;
    if (edits.length >= 200)
      throw new Error('Sync at most 200 changed events at once');
    const response = await request(path);
    if (response.status !== 200)
      throw new Error(
        `Could not read Google event (HTTP ${response.status}); reconnect if access expired`,
      );
    const remote = object(JSON.parse(response.body));
    const edit = planCalendarEdit(subject, row, config, remote);
    if (edit) edits.push(edit);
  }
  return edits;
}
/** Revalidate local review, condition the write on Google's ETag, then checkpoint.
 * A lost acknowledgement is recovered by comparing fresh Google values on preview.
 */
export async function applyCalendarEdit(
  edit: CalendarEdit,
  read: () => Promise<Values>,
  request: CalendarRequest,
  checkpoint: (values: Values) => Promise<void>,
) {
  const check = async () => {
    const current = await read();
    if (
      Object.entries(edit.observed).some(
        ([p, value]) => !same(current[p], value),
      )
    )
      throw new Error('Calendar event changed after preview; preview again');
    return current;
  };
  await check();
  if (Object.keys(edit.patch).length) {
    const response = await request(`${edit.path}?sendUpdates=all`, {
      method: 'PATCH',
      body: JSON.stringify(edit.patch),
      ifMatch: edit.etag,
    });
    if (response.status === 412)
      throw new Error('Google event changed after preview; preview again');
    if (response.status !== 200)
      throw new Error(
        `Google Calendar write failed (HTTP ${response.status}); reconnect with Calendar write access if needed`,
      );
    const remote = object(JSON.parse(response.body));
    if (
      Object.entries(edit.patch).some(
        ([p, value]) => !same(remote[p] ?? '', value),
      )
    )
      throw new Error(
        'Google returned different event values; fetch and review before retrying',
      );
  }
  const current = await check();
  const baseline = object(object(current[IMPORT_BASELINE]).values);
  await checkpoint({
    ...edit.acknowledged,
    [IMPORT_BASELINE]: {
      values: { ...baseline, ...edit.acknowledged },
      previous: baseline,
    },
  });
}
