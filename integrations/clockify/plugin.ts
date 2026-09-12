// @wc-ignore-file
import {
  importRecords,
  type ImportRecord,
} from '../../browser/lib/src/import-records.js';
import { api, id, parse, request, type Config } from './model.js';
declare const settings: Config;
const P = {
  name: 'https://atomicdata.dev/properties/name',
  parent: 'https://atomicdata.dev/properties/parent',
};
interface Host {
  phase?: string;
  trigger?: { at: number };
  http(request: unknown): { status: number; body: string };
  query(property: string, value: string): string[];
  read(subject: string): Record<string, unknown>;
}
export function run(ctx: Host) {
  if (ctx.phase === 'discover') return discover(ctx);
  return importEntries(ctx, settings, ctx.trigger?.at);
}

/** Provider discovery belongs in this bundle, just like mapping and pagination. */
export function discover(ctx: Host) {
  const account = parse(ctx.http(request('user', `${api}/user`))) as any;
  const workspaces = parse(
    ctx.http(request('workspaces', `${api}/workspaces`)),
  ) as any;
  if (!account || typeof account.name !== 'string')
    throw new Error('Clockify returned invalid account details');
  id(account.id);
  if (!Array.isArray(workspaces) || workspaces.length > 1000)
    throw new Error('Clockify returned invalid workspace details');
  const seen = new Set<string>();
  const spaces = workspaces.map(space => {
    if (!space || typeof space.name !== 'string')
      throw new Error('Clockify returned invalid workspace details');
    id(space.id);
    if (seen.has(space.id))
      throw new Error('Clockify returned duplicate workspaces');
    seen.add(space.id);
    return { id: space.id, name: space.name };
  });
  // Only return the fields the picker needs, not the complete provider response.
  return {
    intents: [],
    problems: [],
    discovery: {
      user: { id: account.id, name: account.name },
      workspaces: spaces,
    },
  };
}

export function importEntries(ctx: Host, c: Config, at?: number) {
  id(c.workspace);
  id(c.user);
  let from: number, until: number;
  if (c.lookbackDays !== undefined) {
    if (
      !Number.isInteger(c.lookbackDays) ||
      c.lookbackDays < 1 ||
      c.lookbackDays > 31 ||
      typeof at !== 'number' ||
      !Number.isFinite(at)
    )
      throw new Error(
        'A rolling import needs 1–31 days and a valid host trigger time',
      );
    until = at;
    from = until - c.lookbackDays * 86400000;
  } else {
    from = Date.parse(c.start ?? '');
    until = Date.parse(c.end ?? '');
  }
  if (
    !Number.isFinite(from) ||
    !Number.isFinite(until) ||
    until <= from ||
    until - from > 31 * 86400000 ||
    !Number.isFinite(new Date(from).getTime()) ||
    !Number.isFinite(new Date(until).getTime())
  )
    throw new Error('Choose a date range of at most 31 days');
  const startDate = new Date(from).toISOString(),
    endDate = new Date(until).toISOString();
  const root = `${api}/workspaces/${c.workspace}`;
  const problems: Array<{ severity: 'warning' | 'error'; message: string }> =
    [];
  const list = (operation: string, url: string): Array<Record<string, any>> => {
    const all: Array<Record<string, any>> = [];
    const seen = new Set<string>();
    for (let page = 1; page <= 20; page++) {
      const rows = parse(
        ctx.http(
          request(
            operation,
            `${url}${url.includes('?') ? '&' : '?'}page=${page}&page-size=50`,
            `${operation}-${page}`,
          ),
        ),
      );
      if (!Array.isArray(rows))
        throw new Error('Clockify returned an invalid page');
      for (const row of rows) {
        if (!row || typeof row !== 'object' || typeof row.id !== 'string')
          throw new Error('Clockify returned an invalid record');
        id(row.id);
        if (seen.has(row.id))
          throw new Error(
            'Clockify pagination repeated a record; narrow the range and retry',
          );
        seen.add(row.id);
        all.push(row);
      }
      if (rows.length < 50) return all;
    }
    throw new Error(
      'Import exceeded 1,000 records. Narrow the date range. No partial import was proposed.',
    );
  };
  const matches = (identity: string) => {
    const subjects = ctx.query(c.properties.identity, identity);
    if (subjects.length > 1)
      throw new Error(
        'Duplicate imported identities need review before importing again',
      );
    return subjects[0];
  };
  const projects = list('projects', `${root}/projects`);
  const entries = list(
    'entries',
    `${root}/user/${c.user}/time-entries?start=${encodeURIComponent(startDate)}&end=${encodeURIComponent(endDate)}&in-progress=false`,
  );
  const container = c.container ?? c.table;
  let skipped = 0;
  const records: ImportRecord[] = [];
  const support = new Map<string, string>();
  const moves: Array<{
    op: 'set';
    subject: string;
    set: Record<string, string>;
  }> = [];
  const supportLink = (
    identity: string,
    klass: string,
    name: string,
    localId: string,
  ) => {
    if (support.has(identity)) return support.get(identity)!;
    let parent = container;
    const subject = matches(identity);
    if (subject) {
      const current = ctx.read(subject);
      const classes = current['https://atomicdata.dev/properties/isA'];
      if (
        !Array.isArray(classes) ||
        !classes.includes(klass) ||
        current[c.properties.identity] !== identity
      )
        throw new Error(
          'Imported supporting record has an unexpected identity or class',
        );
      if (typeof current[P.parent] === 'string')
        parent = current[P.parent] as string;
      if (parent === c.drive && container !== c.drive)
        moves.push({ op: 'set', subject, set: { [P.parent]: container } });
    }
    records.push({
      localId,
      sourceId: identity,
      parent,
      isA: [klass],
      values: { [P.name]: name, [c.properties.identity]: identity },
      legacy: { property: c.properties.identity, value: identity },
    });
    const link = `local:${localId}`;
    support.set(identity, link);
    return link;
  };
  for (const entry of entries) {
    if (
      entry.userId !== c.user ||
      (entry.workspaceId && entry.workspaceId !== c.workspace)
    )
      throw new Error(
        'Clockify returned entries for another user or workspace',
      );
    if (!entry.timeInterval?.end) {
      skipped++;
      continue;
    }
    const start = Date.parse(entry.timeInterval.start),
      end = Date.parse(entry.timeInterval.end);
    if (!Number.isFinite(start) || !Number.isFinite(end) || end < start)
      throw new Error('Clockify returned an invalid completed interval');
    if (start < from || start >= until) continue;
    if (entry.type && entry.type !== 'REGULAR') {
      skipped++;
      continue;
    }
    if (
      typeof entry.description !== 'string' ||
      typeof entry.billable !== 'boolean'
    )
      throw new Error('Clockify returned invalid entry fields');
    const identity = `clockify:${c.workspace}:entry:${entry.id}`;
    let project: string | undefined;
    if (entry.projectId) {
      id(entry.projectId);
      const remote = projects.find(p => p.id === entry.projectId);
      if (!remote || typeof remote.name !== 'string')
        throw new Error(
          'An entry references an inaccessible project; no partial import was proposed',
        );
      project = supportLink(
        `clockify:${c.workspace}:project:${entry.projectId}`,
        c.projectClass,
        remote.name,
        `project-${entry.projectId}`,
      );
    }
    const person = supportLink(
      `clockify:${c.workspace}:person:${c.user}`,
      c.personClass,
      c.userName,
      'person',
    );
    records.push({
      sourceId: identity,
      legacy: { property: c.properties.identity, value: identity },
      localId: `entry-${entry.id}`,
      parent: c.table,
      isA: [c.rowClass],
      values: {
        [P.name]: entry.description || 'Time entry',
        [c.properties.start]: start,
        [c.properties.end]: end,
        [c.properties.billable]: entry.billable,
        [c.properties.identity]: identity,
        [c.properties.person]: person,
        ...(project ? { [c.properties.project]: project } : {}),
      },
    });
  }
  const result = importRecords(ctx, records);
  problems.push(...result.problems);
  if (moves.length)
    problems.push({
      severity: 'warning',
      message: `${moves.length} previously imported root records will move inside this app. Their identities and links stay the same.`,
    });
  problems.push({
    severity: 'warning',
    message: `${result.summary.unchanged} unchanged records; ${skipped} running or break entries skipped. Source updates preserve local edits and conflicts need review.`,
  });
  problems.push({
    severity: 'warning',
    message:
      'Import only: tags, task links, rates and custom fields are not mapped. No records are deleted.',
  });
  return { intents: [...result.intents, ...moves], problems };
}
