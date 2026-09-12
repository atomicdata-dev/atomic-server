import {
  claimImportIdentity,
  IMPORT_LOCAL_ID,
} from '../../browser/lib/src/import-records.js';
// @wc-ignore-file
/** Entire provider executes in QuickJS/WASM; host applies all durable effects. */
import {
  reconcileRecord,
  type SyncRecord,
} from '../../browser/lib/src/plugin-reconcile.js';
import type {
  ConnectionState,
  ExternalReceipt,
} from '../../browser/lib/src/plugin-connection.js';
import {
  P,
  uuid,
  parse,
  request,
  equal,
  projectPage,
  projectRow,
  pagePatch,
  rowPatch,
  projectView,
  projectLocalView,
  viewPatch,
  type Config,
  type Projection,
} from './model.js';
globalThis.structuredClone ??= ((v: unknown) =>
  v === undefined
    ? undefined
    : JSON.parse(JSON.stringify(v))) as typeof structuredClone;
interface Change {
  kind: 'page' | 'schema' | 'view';
  id?: string;
  subject?: string;
  local?: Projection;
  remote?: Projection;
  desired: Projection;
}
interface Proposal {
  dataSource: string;
  changes: Change[];
  conflicts: { id?: string; fields: string[] }[];
}
interface Cursor {
  index: number;
  stage: string;
  id?: string;
  subject?: string;
  records: unknown[];
}
interface Input {
  phase: 'preview' | 'step';
  config: Config;
  connection: ConnectionState;
  proposal?: Proposal;
  cursor?: Cursor;
  result?: any;
  http(r: unknown): ExternalReceipt;
  read(s: string): Record<string, any>;
  query(p: string, v: string): string[];
}
export function run(input: Input): unknown {
  const c = input.config;
  uuid(c.dataSource);
  if (
    !c.fields.length ||
    new Set(c.fields.map(f => f.id)).size !== c.fields.length ||
    new Set(c.fields.map(f => f.property)).size !== c.fields.length
  )
    throw new Error('Invalid or duplicate Notion field mappings');
  const read = (operation: string, path: string, body?: unknown) =>
    parse(
      input.http(
        request(operation, body === undefined ? 'GET' : 'POST', path, body),
      ),
    );
  const schema = () => {
    const source = read('schema', `/data_sources/${c.dataSource}`);
    if (uuid(source.id) !== uuid(c.dataSource))
      throw new Error('Unexpected data source');
    for (const f of c.fields) {
      const p: any = Object.values(source.properties).find(
        (p: any) => p.id === f.id,
      );
      if (!p || p.type !== f.type)
        throw new Error(`Mapped property ${f.id} changed type or was removed`);
      if (f.options) {
        const ids = (p[f.type]?.options ?? []).map((o: any) => o.id).sort();
        if (!equal(ids, Object.keys(f.options).sort()))
          throw new Error(
            'Select options changed; refresh mapping before syncing',
          );
        for (const option of p[f.type].options) {
          if (
            f.optionNames &&
            (option.name !== f.optionNames[option.id] ||
              input.read(f.options[option.id])[P.name] !==
                f.optionNames[option.id])
          )
            throw new Error(
              'Select option names changed; review the mapping before syncing',
            );
        }
      }
    }
    return source;
  };
  const row = (subject: string) => {
    const value = input.read(subject);
    const binding = input.connection.records[`page:${value[c.identity]}`];
    return projectRow(value, c, binding?.baseline as Projection | undefined);
  };
  const page = (id: string) => {
    const p = read('page', `/pages/${uuid(id)}`);
    if (uuid(p.id) !== uuid(id)) throw new Error('Unexpected Notion page');
    return p;
  };
  const view = (id: string) => {
    const v = read('view', `/views/${uuid(id)}`);
    if (uuid(v.id) !== uuid(id)) throw new Error('Unexpected Notion view');
    return v;
  };
  const remote = (change: Change): Projection =>
    change.kind === 'page'
      ? projectPage(page(change.id!), c)
      : change.kind === 'view'
        ? projectView(view(change.id!), c)
        : {
            name: (
              Object.values(schema().properties).find(
                (p: any) => p.id === change.id,
              ) as any
            ).name,
          };
  const local = (
    change: Change,
    subject = change.subject,
  ): Projection | undefined =>
    !subject
      ? undefined
      : change.kind === 'page'
        ? row(subject)
        : change.kind === 'schema'
          ? { name: input.read(subject)[P.name] }
          : projectLocalView(
              input.read(subject),
              c,
              c.views.find(v => v.id === change.id)!,
            );
  if (input.phase === 'preview') {
    const source = schema();
    const proposal: Proposal = {
      dataSource: c.dataSource,
      changes: [],
      conflicts: [],
    };
    const add = (change: Omit<Change, 'desired'>) => {
      const key = change.id ? `${change.kind}:${change.id}` : undefined;
      const bound = key ? input.connection.records[key] : undefined;
      if (bound && bound.local !== change.subject) {
        proposal.conflicts.push({
          id: change.id,
          fields: ['Missing or rebound Atomic identity'],
        });
        return;
      }
      const decision = reconcileRecord(
        bound?.baseline as SyncRecord,
        change.local,
        change.remote,
      );
      if (decision.conflicts.length) {
        proposal.conflicts.push({
          id: change.id,
          fields: decision.conflicts.map(x => x.property),
        });
        return;
      }
      proposal.changes.push({
        ...change,
        desired: {
          ...(change.remote ?? change.local),
          ...decision.remote,
        } as Projection,
      });
    };
    for (const f of c.fields) {
      const p: any = Object.values(source.properties).find(
        (p: any) => p.id === f.id,
      );
      add({
        kind: 'schema',
        id: f.id,
        subject: f.property,
        local: { name: input.read(f.property)[P.name] },
        remote: { name: p.name },
      });
    }
    for (const v of c.views)
      add({
        kind: 'view',
        id: v.id,
        subject: v.subject,
        local: local({
          kind: 'view',
          id: v.id,
          subject: v.subject,
          desired: {},
        }),
        remote: projectView(view(v.id), c),
      });
    const rows = input
      .query(P.parent, c.table)
      .filter(s => input.read(s)[P.isA]?.includes(c.rowClass));
    const byId = new Map<string, string>();
    for (const s of rows) {
      const id = input.read(s)[c.identity];
      if (id) {
        uuid(id);
        if (byId.has(id)) throw new Error('Duplicate Notion page identity');
        byId.set(id, s);
      } else add({ kind: 'page', subject: s, local: row(s) });
    }
    const seen = new Set<string>();
    const cursors = new Set<string>();
    let cursor: string | undefined;
    for (let batch = 0; ; batch++) {
      if (batch >= 100) throw new Error('Notion pilot scan exceeds 100 pages');
      const result = read('query', `/data_sources/${c.dataSource}/query`, {
        page_size: 100,
        ...(cursor ? { start_cursor: cursor } : {}),
      });
      if (
        !Array.isArray(result.results) ||
        typeof result.has_more !== 'boolean'
      )
        throw new Error('Invalid Notion query page');
      for (const p of result.results) {
        const id = uuid(p.id);
        if (seen.has(id))
          throw new Error('Duplicate page during scan; retry a stable read');
        seen.add(id);
        const subject = byId.get(id);
        add({
          kind: 'page',
          id,
          subject,
          local: subject ? row(subject) : undefined,
          remote: projectPage(p, c),
        });
      }
      if (!result.has_more) break;
      if (
        typeof result.next_cursor !== 'string' ||
        !result.next_cursor ||
        cursors.has(result.next_cursor)
      )
        throw new Error('Incomplete or looping Notion pagination');
      cursor = result.next_cursor;
      cursors.add(cursor!);
    }
    for (const [id] of byId)
      if (!seen.has(id))
        proposal.conflicts.push({
          id,
          fields: ['Missing or inaccessible page; no deletion inferred'],
        });
    // Missing baseline bindings are not silently forgotten even if both sides disappeared.
    for (const key of Object.keys(input.connection.records))
      if (key.startsWith('page:') && !seen.has(key.slice(5)))
        proposal.conflicts.push({
          id: key.slice(5),
          fields: ['Previously synced page missing'],
        });
    return {
      kind: 'preview',
      proposal,
      problems: proposal.conflicts.map(x => ({
        severity: 'error',
        message: `${x.id ?? 'New row'}: ${x.fields.join(', ')}`,
      })),
    };
  }
  if (
    !input.proposal ||
    input.proposal.dataSource !== c.dataSource ||
    input.proposal.conflicts.length
  )
    throw new Error('A conflict-free approved Notion preview is required');
  let cursor = input.cursor ?? { index: 0, stage: 'start', records: [] };
  const effect = (value: unknown, next: Cursor) => ({
    kind: 'effect',
    effect: value,
    cursor: next,
  });
  const external = (
    operation: string,
    path: string,
    body: unknown,
    next: Cursor,
  ) =>
    effect(
      {
        kind: 'external',
        id: `${cursor.index}:remote`,
        request: request(
          operation,
          operation === 'create' ? 'POST' : 'PATCH',
          path,
          body,
          `${cursor.index}:remote`,
        ),
      },
      next,
    );
  for (let i = 0; i < 8; i++) {
    if (cursor.stage === 'done') return { kind: 'complete' };
    if (cursor.index === input.proposal.changes.length)
      return effect(
        { kind: 'checkpoint', id: 'checkpoint', records: cursor.records },
        { ...cursor, stage: 'done' },
      );
    const change = input.proposal.changes[cursor.index];
    if (cursor.stage === 'start') {
      schema(); // A schema/type change must stop before any provider mutation.
      if (!equal(local(change), change.local))
        throw new Error('Atomic data changed after preview');
      if (change.id && !equal(remote(change), change.remote))
        throw new Error('Notion data changed after preview');
      cursor = {
        ...cursor,
        id: change.id,
        subject: change.subject,
        stage: 'local',
      };
      if (change.kind === 'page') {
        const properties = pagePatch(change.desired, change.remote, c);
        if (!change.id)
          return external(
            'create',
            '/pages',
            { parent: { data_source_id: c.dataSource }, properties },
            { ...cursor, stage: 'created' },
          );
        if (Object.keys(properties).length)
          return external(
            'update',
            `/pages/${change.id}`,
            { properties },
            cursor,
          );
      } else if (
        change.kind === 'schema' &&
        !equal(change.desired, change.remote)
      )
        return external(
          'rename',
          `/data_sources/${c.dataSource}`,
          { properties: { [change.id!]: { name: change.desired.name } } },
          cursor,
        );
      else if (change.kind === 'view') {
        const patch = viewPatch(change.desired, view(change.id!), c);
        if (Object.keys(patch).length)
          return external('view-update', `/views/${change.id}`, patch, cursor);
      }
    } else if (cursor.stage === 'created') {
      const p = parse(input.result);
      projectPage(p, c);
      cursor = { ...cursor, id: uuid(p.id), stage: 'local' };
    } else if (cursor.stage === 'local') {
      const actual = { ...change, id: cursor.id };
      if (!equal(remote(actual), change.desired))
        throw new Error(
          'Notion has not converged; keep the saved run for reconciliation',
        );
      const here = local(change, cursor.subject);
      if (!equal(here, change.local) && !equal(here, change.desired))
        throw new Error('Atomic data changed during sync');
      let set: Record<string, unknown>;
      let remove: string[] = [];
      if (change.kind === 'page') {
        // Ensure a resumed import cannot create a second card with the same ID.
        const matches = input
          .query(c.identity, cursor.id!)
          .filter(s => input.read(s)[P.parent] === c.table);
        if (matches.some(s => s !== cursor.subject))
          throw new Error('Unexpected page binding appeared during sync');
        ({ set, remove } = rowPatch(change.desired, c));
        Object.assign(
          set,
          claimImportIdentity(
            input,
            c.table,
            `notion:${uuid(c.dataSource)}:page:${uuid(cursor.id!)}`,
            cursor.subject,
          ),
        );
        set[c.identity] = cursor.id;
        if (!cursor.subject && input.connection.revision > 0)
          set[c.arrival] = 'remote';
      } else if (change.kind === 'schema')
        set = { [P.name]: change.desired.name };
      else {
        set = {
          [P.name]: change.desired.name,
          [P.kind]: change.desired.kind === 'board' ? 'kanban' : 'table',
          [P.columns]: (change.desired.columns as string[]).map(
            id => c.fields.find(f => f.id === id)!.property,
          ),
        };
        if (change.desired.group)
          set[P.group] = c.fields.find(
            f => f.id === change.desired.group,
          )!.property;
        else remove.push(P.group);
      }
      if (
        equal(here, change.desired) &&
        (change.kind !== 'page' ||
          (input.read(cursor.subject!)[c.identity] === cursor.id &&
            input.read(cursor.subject!)[IMPORT_LOCAL_ID] ===
              `notion:${uuid(c.dataSource)}:page:${uuid(cursor.id!)}` &&
            input.read(cursor.subject!)[P.name] ===
              change.desired[c.fields.find(f => f.type === 'title')!.id]))
      )
        cursor = { ...cursor, stage: 'verify' };
      else {
        const intents: unknown[] = cursor.subject
          ? [
              { op: 'set', subject: cursor.subject, set },
              ...(remove.length
                ? [
                    {
                      op: 'remove',
                      subject: cursor.subject,
                      properties: remove,
                    },
                  ]
                : []),
            ]
          : [
              {
                op: 'create',
                localId: 'row',
                parent: c.table,
                isA: [c.rowClass],
                set,
              },
            ];
        return effect(
          {
            kind: 'atomic',
            id: `${cursor.index}:atomic`,
            verdict: { intents, problems: [] },
          },
          { ...cursor, stage: 'written' },
        );
      }
    } else if (cursor.stage === 'written') {
      const subject = input.result.outcomes?.[0]?.subject;
      if (!subject) throw new Error('Missing Atomic receipt');
      cursor = { ...cursor, subject, stage: 'verify' };
    } else if (cursor.stage === 'verify') {
      const l = local(change, cursor.subject);
      const r = remote({ ...change, id: cursor.id });
      if (!equal(l, change.desired) || !equal(r, change.desired))
        throw new Error('Both sides must agree before checkpointing');
      cursor = {
        index: cursor.index + 1,
        stage: 'start',
        records: [
          ...cursor.records,
          {
            remote: `${change.kind}:${cursor.id}`,
            local: cursor.subject,
            local_projection: l,
            remote_projection: r,
          },
        ],
      };
      return { kind: 'continue', cursor };
    } else throw new Error('Unknown Notion continuation');
  }
  throw new Error('Notion continuation exceeded transition budget');
}
