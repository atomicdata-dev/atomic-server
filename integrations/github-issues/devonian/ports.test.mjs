import { expect, it } from 'vitest';
import { GitHubPort, AtomicPort } from './ports.mjs';
import {
  trackerAction,
  trackerActions,
  trackerOperations,
} from '../tracker-actions.js';
import { manifest } from '../adapter.js';
import { validateManifest } from '../../../browser/lib/src/plugin-manifest.js';

it('declares and prepares scoped issue/comment actions with validated arguments', () => {
  const original = manifest('owner/repo');
  const m = validateManifest({
    ...original,
    actions: [...original.actions, ...trackerActions],
    operations: [
      ...original.operations,
      ...trackerOperations('https://api.github.com/repos/owner/repo/issues'),
    ],
  });
  for (const [action, args] of [
    ['list_issues', { page: 1 }],
    ['list_comments', { number: 5, page: 2 }],
    ['create_comment', { number: 5, body: 'Hello' }],
    ['get_comment', { id: 9 }],
    ['update_comment', { id: 9, body: 'Edit' }],
    ['update_issue', { number: 5, title: 'Title', body: '', state: 'closed' }],
    ['add_doing_label', { number: 5 }],
    ['remove_doing_label', { number: 5 }],
  ]) {
    const intent = trackerAction('owner/repo', action, args);
    expect(
      intent.url.startsWith('https://api.github.com/repos/owner/repo/issues'),
    ).toBe(true);
    expect(m.actions.find(a => a.name === action).operation).toBe(
      intent.operation,
    );
    expect(
      m.operations.some(
        o => o.id === intent.operation && o.method === intent.method,
      ),
    ).toBe(true);
  }
  expect(() =>
    trackerAction('owner/repo', 'get_comment', { id: '../escape' }),
  ).toThrow();
  expect(() =>
    trackerAction('owner/repo', 'list_issues', { page: 101 }),
  ).toThrow();
  expect(() =>
    trackerAction('owner/repo', 'create_comment', { number: 1, body: '' }),
  ).toThrow();
});

function github() {
  const issues = new Map([
    [
      1,
      { number: 1, title: 'First', body: '', state: 'open', labels: ['bug'] },
    ],
  ]);
  const comments = new Map();
  const receipts = new Map();
  const writes = [];
  const port = new GitHubPort(
    null,
    { repository: 'owner/repo' },
    async (action, args, id) => {
      const isWrite = /^(create|update|add|remove)_/.test(action);
      if (isWrite && receipts.has(id)) return receipts.get(id);
      let value;
      if (isWrite) writes.push(action);
      switch (action) {
        case 'get_issue':
          value = issues.get(args.number);
          break;
        case 'list_issues':
          value = [...issues.values()];
          break;
        case 'create_issue':
          value = {
            number: issues.size + 1,
            ...args,
            state: 'open',
            labels: [],
          };
          issues.set(value.number, value);
          break;
        case 'update_issue':
          value = issues.get(args.number);
          Object.assign(value, args);
          break;
        case 'add_doing_label':
          value = issues.get(args.number);
          value.labels.push('atomic:doing');
          break;
        case 'remove_doing_label':
          value = issues.get(args.number);
          value.labels = value.labels.filter(l => l !== 'atomic:doing');
          break;
        case 'create_comment':
          value = {
            id: comments.size + 1,
            body: args.body,
            issue_url: `https://api.github.com/repos/owner/repo/issues/${args.number}`,
          };
          comments.set(value.id, value);
          break;
        case 'get_comment':
          value = comments.get(args.id);
          break;
        case 'list_comments':
          value = [...comments.values()];
          break;
        case 'update_comment':
          value = comments.get(args.id);
          value.body = args.body;
          break;
        default:
          throw new Error(action);
      }
      const receipt = { status: 200, body: JSON.stringify(value) };
      if (isWrite) receipts.set(id, receipt);
      return receipt;
    },
  );
  return { port, issues, comments, writes };
}

it('creates closed/doing issues and reopens while preserving unrelated labels', async () => {
  const { port, issues } = github();
  const value = { title: 'Created closed', body: 'Markdown', status: 'Done' };
  const row = await port.create('issue', value, 'stable-create');
  expect(issues.get(row.id).state).toBe('closed');
  await port.create('issue', value, 'stable-create');
  expect(issues.size).toBe(2);
  await port.update('issue', 1, { ...value, status: 'Doing' }, 'doing');
  expect(issues.get(1).labels).toEqual(['bug', 'atomic:doing']);
  await port.update('issue', 1, value, 'close');
  await port.update('issue', 1, { ...value, status: 'Todo' }, 'reopen');
  expect(issues.get(1).state).toBe('open');
  expect(issues.get(1).labels).toEqual(['bug']);
});

it('creates/edits comments with replay-safe IDs and rejects another issue’s comment', async () => {
  const { port, comments } = github();
  const context = { issueId: 1 };
  await port.create(
    'comment:x',
    { body: 'Hi' },
    'comment-create',
    undefined,
    context,
  );
  await port.create(
    'comment:x',
    { body: 'Hi' },
    'comment-create',
    undefined,
    context,
  );
  expect(comments.size).toBe(1);
  await port.update(
    'comment:x',
    1,
    { body: 'Edited' },
    'comment-edit',
    undefined,
    context,
  );
  expect(comments.get(1).body).toBe('Edited');
  await expect(port.get('comment:x', 1, { issueId: 2 })).rejects.toThrow(
    'another issue',
  );
});

it('fails on provider errors and scans all pages without importing pull requests', async () => {
  const f = github();
  const row = f.issues.get(1);
  let calls = 0;
  const port = new GitHubPort(null, { repository: 'owner/repo' }, async () => ({
    status: 200,
    body: JSON.stringify(
      ++calls === 1
        ? Array.from({ length: 100 }, (_, i) => ({
            ...row,
            number: i + 1,
            ...(i === 0 ? { pull_request: {} } : {}),
          }))
        : [],
    ),
  }));
  expect(await port.list('issue')).toHaveLength(99);
  expect(calls).toBe(2);
  port.call = async () => ({ status: 429, body: '{}' });
  await expect(port.list('issue')).rejects.toThrow('429');
});

it('Atomic creates reuse native localId after a lost acknowledgement', async () => {
  const stored = new Map();
  let lose = true;
  const store = {
    getServerUrl: () => 'https://atomic.example',
    findByLocalId: async (_drive, parent, key) =>
      [...stored.values()].find(r => r.parent === parent && r.key === key),
    newResource: async ({ parent, propVals }) => {
      const r = {
        subject: `did:ad:${stored.size + 1}`,
        parent,
        key: propVals['https://atomicdata.dev/properties/localId'],
        async save() {
          stored.set(r.subject, r);
          if (lose) {
            lose = false;
            throw new Error('Lost acknowledgement');
          }
        },
      };
      return r;
    },
  };
  const port = new AtomicPort(store, {
    connection: {
      table: 'did:ad:table',
      drive: 'did:ad:drive',
      tags: { Todo: 'https://atomicdata.dev/task/v1/todo' },
    },
  });
  const value = { title: 'Same', body: '', status: 'Todo' };
  port.get = async (_entity, id) => ({ id, value });
  port.findByLocalId = (parent, key) => store.findByLocalId('', parent, key);
  await expect(port.create('issue', value, 'key')).rejects.toThrow(
    'Lost acknowledgement',
  );
  expect((await port.create('issue', value, 'key')).id).toBe('did:ad:1');
  expect(stored.size).toBe(1);
});
