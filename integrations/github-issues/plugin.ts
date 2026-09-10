import {
  claimImportIdentity,
  IMPORT_LOCAL_ID,
} from '../../browser/lib/src/import-records.js';
/** This entire module runs inside Atomic's QuickJS/WASM sandbox. */
import {
  preview,
  project,
  endpoint,
  request,
  type Preview,
  type Card,
  type Issue,
  type Projection,
} from './adapter.js';
import type {
  ConnectionState,
  ExternalReceipt,
} from '../../browser/lib/src/plugin-connection.js';

const parent = 'https://atomicdata.dev/properties/parent';
const isA = 'https://atomicdata.dev/properties/isA';
const name = 'https://atomicdata.dev/properties/name';
// QuickJS has no structuredClone. This plugin only clones JSON projections.
globalThis.structuredClone ??= ((value: unknown) =>
  value === undefined
    ? undefined
    : JSON.parse(JSON.stringify(value))) as typeof structuredClone;

interface Config {
  repository: string;
  table: string;
  rowClass: string;
  status: string;
  number: string;
  body: string;
  arrival?: string;
  tags: Record<Projection['status'], string>;
}
interface Cursor {
  index: number;
  stage: string;
  number?: number;
  subject?: string;
  records: unknown[];
}
interface Input {
  phase: 'preview' | 'step' | 'action';
  action?: string;
  arguments?: Record<string, unknown>;
  config: Config;
  connection: ConnectionState;
  proposal?: Preview;
  cursor?: Cursor;
  result?: any;
  http(request: unknown): ExternalReceipt;
  read(subject: string): Record<string, unknown>;
  query(property: string, value: string): string[];
}
const equal = (a: Projection | undefined, b: Projection | undefined) =>
  a === b ||
  (!!a &&
    !!b &&
    a.title === b.title &&
    a.body === b.body &&
    a.status === b.status);
export async function run(input: Input): Promise<unknown> {
  const config = input.config;
  if (input.phase === 'action') {
    const root = endpoint(config.repository);
    const args = input.arguments ?? {};
    if (input.action === 'get_issue') {
      if (!Number.isSafeInteger(args.number) || Number(args.number) <= 0)
        throw new Error('Choose a positive issue number');
      return request('get', 'GET', `${root}/${args.number}`, 'action');
    }
    if (input.action === 'create_issue') {
      if (
        typeof args.title !== 'string' ||
        !args.title.trim() ||
        args.title.length > 256
      )
        throw new Error('Issue title must contain 1 to 256 characters');
      return request('create', 'POST', root, 'action', {
        title: args.title,
        body: args.body ?? '',
      });
    }
    throw new Error('Unknown integration action');
  }
  if (
    !config ||
    !config.table ||
    !config.rowClass ||
    !config.tags ||
    Object.keys(config.tags).length !== 3
  )
    throw new Error('Configure the connection before running it');
  const root = endpoint(config.repository);
  const card = (subject: string): Card | undefined => {
    const row = input.read(subject);
    if (
      !(row[isA] as string[] | undefined)?.includes(config.rowClass) ||
      row[parent] !== config.table
    )
      return;
    const selected = row[config.status] as string[] | undefined;
    const status = selected?.length
      ? Object.entries(config.tags).find(
          ([, id]) => selected.length === 1 && selected[0] === id,
        )?.[0]
      : 'Todo';
    if (!status) throw new Error('Choose exactly one kanban status');
    const number = row[config.number];
    if (
      number !== undefined &&
      (!Number.isSafeInteger(number) || Number(number) <= 0)
    )
      throw new Error('Invalid GitHub issue number');
    return {
      subject,
      ...(number === undefined ? {} : { number: number as number }),
      value: {
        title: String(row[name] ?? ''),
        body: String(row[config.body] ?? ''),
        status: status as Projection['status'],
      },
    };
  };
  const find = (number: number) => {
    const matches = input
      .query(config.number, String(number))
      .map(card)
      .filter((r): r is Card => r !== undefined);
    if (matches.length > 1) throw new Error('Duplicate issue identity');
    return matches[0];
  };
  const issue = (number: number): Issue => {
    const response = input.http(
      request('get', 'GET', `${root}/${number}`, 'read'),
    );
    if (response.status !== 200)
      throw new Error(
        `GitHub read failed (${response.status}); no deletion inferred`,
      );
    const value = JSON.parse(response.body) as Issue;
    if ('pull_request' in value || value.number !== number)
      throw new Error('Expected the selected issue');
    project(value);
    return value;
  };
  if (input.phase === 'preview') {
    const proposal = await preview(
      {
        read: async intent => input.http(intent),
        state: async () => input.connection,
        cards: async () =>
          input
            .query(parent, config.table)
            .map(card)
            .filter((r): r is Card => r !== undefined),
      },
      config.repository,
    );
    return {
      kind: 'preview',
      proposal,
      problems: proposal.conflicts.map(c => ({
        severity: 'error',
        message: `Issue ${c.number ?? c.subject}: ${c.fields.join(', ')}`,
      })),
    };
  }
  if (
    !input.proposal ||
    input.proposal.repository !== config.repository ||
    input.proposal.conflicts.length
  )
    throw new Error('An approved conflict-free proposal is required');
  let cursor: Cursor = input.cursor ?? {
    index: 0,
    stage: 'start',
    records: [],
  };
  const effect = (value: unknown, next: Cursor) => ({
    kind: 'effect',
    effect: value,
    cursor: next,
  });
  const external = (
    operation: string,
    method: string,
    url: string,
    suffix: string,
    next: Cursor,
    body?: unknown,
  ) => {
    const id = `${cursor.index}:${suffix}`;
    return effect(
      {
        kind: 'external',
        id,
        request: request(operation, method, url, id, body),
      },
      next,
    );
  };
  // Pure transitions may be folded into the same invocation. Every write yields.
  for (let transitions = 0; transitions < 12; transitions++) {
    if (cursor.stage === 'done') return { kind: 'complete' };
    if (cursor.index === input.proposal.changes.length)
      return effect(
        { kind: 'checkpoint', id: 'checkpoint', records: cursor.records },
        { ...cursor, stage: 'done' },
      );
    const change = input.proposal.changes[cursor.index];
    const desired = change.desired;
    if (cursor.stage === 'start') {
      const local = change.subject
        ? card(change.subject)
        : change.number
          ? find(change.number)
          : undefined;
      if (change.subject && (!local || !equal(local.value, change.local)))
        throw new Error('Card changed after preview');
      if (!change.subject && local)
        throw new Error('An imported card appeared after preview');
      if (change.number && local && local.number !== change.number)
        throw new Error('Card identity changed after preview');
      if (change.number === undefined)
        return external(
          'create',
          'POST',
          root,
          'create',
          { ...cursor, stage: 'created', subject: local?.subject },
          {
            title: desired.title,
            body: desired.body,
            labels: desired.status === 'Doing' ? ['atomic:doing'] : [],
          },
        );
      const remote = project(issue(change.number));
      if (!equal(remote, change.remote))
        throw new Error('Issue changed after preview');
      cursor = {
        ...cursor,
        stage: 'patch',
        number: change.number,
        subject: local?.subject,
      };
    } else if (cursor.stage === 'created') {
      const created = JSON.parse(input.result.body) as Issue;
      project(created);
      cursor = { ...cursor, number: created.number, stage: 'patch' };
    } else if (cursor.stage === 'patch') {
      const patch: Record<string, unknown> = {};
      if (change.remote && change.remote.title !== desired.title)
        patch.title = desired.title;
      if (change.remote && change.remote.body !== desired.body)
        patch.body = desired.body;
      if (
        (!change.remote && desired.status === 'Done') ||
        (change.remote &&
          (change.remote.status === 'Done') !== (desired.status === 'Done'))
      )
        patch.state = desired.status === 'Done' ? 'closed' : 'open';
      const next = { ...cursor, stage: 'labels' };
      if (Object.keys(patch).length)
        return external(
          'update',
          'PATCH',
          `${root}/${cursor.number}`,
          'update',
          next,
          patch,
        );
      cursor = next;
    } else if (cursor.stage === 'labels') {
      const current = issue(cursor.number!);
      const doing = current.labels.some(
        l =>
          (typeof l === 'string' ? l : l.name).toLowerCase() === 'atomic:doing',
      );
      const next = { ...cursor, stage: 'local' };
      if (desired.status === 'Doing' && !doing)
        return external(
          'doing-add',
          'POST',
          `${root}/${cursor.number}/labels`,
          'label',
          next,
          {
            labels: ['atomic:doing'],
          },
        );
      if (desired.status !== 'Doing' && doing)
        return external(
          'doing-remove',
          'DELETE',
          `${root}/${cursor.number}/labels/atomic%3Adoing`,
          'label',
          next,
        );
      cursor = next;
    } else if (cursor.stage === 'local') {
      if (!equal(project(issue(cursor.number!)), desired))
        throw new Error('GitHub did not converge; checkpoint paused');
      const local = cursor.subject
        ? card(cursor.subject)
        : find(cursor.number!);
      if (
        cursor.subject &&
        (!local ||
          (!equal(local.value, change.local) && !equal(local.value, desired)))
      )
        throw new Error('Card changed during sync');
      if (!cursor.subject && local)
        throw new Error(
          'An unexpected card appeared; reconcile before creating',
        );
      const identity = `github:${config.repository.toLowerCase()}:issue:${cursor.number}`;
      const set = {
        ...claimImportIdentity(input, config.table, identity, local?.subject),
        [name]: desired.title,
        [config.body]: desired.body,
        [config.status]: [config.tags[desired.status]],
        [config.number]: cursor.number,
        ...(config.arrival &&
        !local &&
        change.remote &&
        input.connection.revision > 0
          ? { [config.arrival]: 'remote' }
          : {}),
      };
      if (
        local &&
        equal(local.value, desired) &&
        local.number === cursor.number &&
        input.read(local.subject)[IMPORT_LOCAL_ID] === identity
      )
        cursor = { ...cursor, subject: local.subject, stage: 'verify' };
      else
        return effect(
          {
            kind: 'atomic',
            id: `${cursor.index}:card`,
            verdict: {
              intents: [
                local
                  ? { op: 'set', subject: local.subject, set }
                  : {
                      op: 'create',
                      localId: 'card',
                      parent: config.table,
                      isA: [config.rowClass],
                      set,
                    },
              ],
              problems: [],
            },
          },
          { ...cursor, stage: 'written' },
        );
    } else if (cursor.stage === 'written') {
      const subject = input.result.outcomes?.[0]?.subject;
      if (!subject) throw new Error('Atomic receipt is missing its subject');
      cursor = { ...cursor, subject, stage: 'verify' };
    } else if (cursor.stage === 'verify') {
      const local = card(cursor.subject!);
      const remote = project(issue(cursor.number!));
      if (
        !local ||
        local.number !== cursor.number ||
        !equal(local.value, desired) ||
        !equal(remote, desired)
      )
        throw new Error('Both sides must agree before checkpointing');
      cursor = {
        index: cursor.index + 1,
        stage: 'start',
        records: [
          ...cursor.records,
          {
            remote: String(cursor.number),
            local: local.subject,
            local_projection: local.value,
            remote_projection: remote,
          },
        ],
      };
      // Return a read-only continuation instead of doing unbounded work per invocation.
      return { kind: 'continue', cursor };
    } else throw new Error('Unknown connection continuation');
  }
  throw new Error('Too many pure transitions');
}
