import { expect, it } from 'vitest';
import * as devonian from 'devonian';
import { Bridge } from './bridge.mjs';

function fixture(snapshot) {
  let saved = snapshot;
  const makePort = scope => ({
    scope,
    rows: new Map(),
    receipts: new Map(),
    writes: 0,
    lose: false,
    async list(entity) {
      return [...this.rows.values()].filter(r => r.entity === entity);
    },
    async get(entity, id) {
      const row = this.rows.get(id);
      if (!row || row.entity !== entity) throw new Error('Missing record');
      return structuredClone(row);
    },
    async create(entity, value, key, metadata) {
      if (this.receipts.has(key)) return this.receipts.get(key);
      const id = this.rows.size + 1;
      const row = { id, entity, value: structuredClone(value), metadata };
      this.rows.set(id, row);
      this.receipts.set(key, row);
      this.writes++;
      if (this.lose) {
        this.lose = false;
        throw new Error('Lost response');
      }
      return row;
    },
    async update(entity, id, value) {
      const row = await this.get(entity, id);
      this.rows.set(id, { ...row, value: structuredClone(value) });
      this.writes++;
    },
  });
  const local = makePort('https://atomic.example/bridge');
  const remote = makePort('https://github.com/acme/repo');
  const open = () =>
    new Bridge({
      devonian,
      local,
      remote,
      snapshot: saved,
      base: 'https://bridge.example/sync',
      save: async s => {
        saved = structuredClone(s);
      },
    });
  return { local, remote, open, saved: () => saved };
}
const issue = (id, title = 'Same title') => ({
  id,
  entity: 'issue',
  value: { title, body: '', status: 'Todo' },
});

it('syncs creation both ways without deduplicating equal content, then no-ops after restart', async () => {
  const f = fixture();
  f.local.rows.set(1, issue(1));
  f.remote.rows.set(1, issue(1));
  await f.open().sync();
  expect(f.local.rows.size).toBe(2);
  expect(f.remote.rows.size).toBe(2);
  const writes = f.local.writes + f.remote.writes;
  await f.open().sync();
  expect(f.local.writes + f.remote.writes).toBe(writes);
});

it('merges independent title/body edits and propagates close/reopen', async () => {
  const f = fixture();
  f.remote.rows.set(1, issue(1));
  await f.open().sync();
  f.local.rows.get(1).value.title = 'Local title';
  f.remote.rows.get(1).value.body = 'Remote body';
  f.local.rows.get(1).value.status = 'Done';
  await f.open().sync();
  expect(f.remote.rows.get(1).value).toEqual({
    title: 'Local title',
    body: 'Remote body',
    status: 'Done',
  });
  f.remote.rows.get(1).value.status = 'Todo';
  await f.open().sync();
  expect(f.local.rows.get(1).value.status).toBe('Todo');
});

it('syncs comments and edits both ways, preserving source metadata', async () => {
  const f = fixture();
  f.remote.rows.set(1, issue(1));
  await f.open().sync();
  const parent = Object.keys(f.saved().records)[0];
  const entity = `comment:${parent}`;
  f.remote.rows.set(2, {
    id: 2,
    entity,
    value: { body: 'GitHub comment' },
    metadata: { author: 'octocat' },
  });
  f.local.rows.set(2, { id: 2, entity, value: { body: 'Atomic comment' } });
  await f.open().sync();
  expect(f.local.rows.get(3).metadata).toEqual({ author: 'octocat' });
  expect(f.remote.rows.get(3).value.body).toBe('Atomic comment');
  f.local.rows.get(3).value.body = 'Edited';
  await f.open().sync();
  expect(f.remote.rows.get(2).value.body).toBe('Edited');
});

it('stops on same-field conflicts and missing records without deleting either side', async () => {
  const f = fixture();
  f.remote.rows.set(1, issue(1));
  await f.open().sync();
  f.local.rows.get(1).value.title = 'A';
  f.remote.rows.get(1).value.title = 'B';
  await expect(f.open().sync()).rejects.toThrow('Conflict');
  expect(f.local.rows.get(1).value.title).toBe('A');
  f.remote.rows.delete(1);
  await expect(f.open().sync()).rejects.toThrow('Missing');
  expect(f.local.rows.size).toBe(1);
});

it('reuses the same create identity after a lost receipt and restart', async () => {
  const f = fixture();
  f.local.rows.set(1, issue(1));
  f.remote.lose = true;
  await expect(f.open().sync()).rejects.toThrow('Lost response');
  await f.open().sync();
  expect(f.remote.rows.size).toBe(1);
  expect(f.remote.writes).toBe(1);
});
