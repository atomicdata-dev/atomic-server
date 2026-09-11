import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { work } from './worker.mjs';
import { core, fields } from './model.mjs';

function fixture() {
  const props = Object.fromEntries(Object.keys(fields).map(k => [k, k]));
  const config = {
    drive: 'drive',
    app: 'app',
    data: 'data',
    rowClass: 'conversation',
    turnClass: 'turn',
    approvalClass: 'approval',
    properties: props,
    workspace: '/fixed/workspace',
  };
  const rows = new Map();
  let id = 0;
  const row = (subject, parent, isA, values = {}) => {
    const r = {
      subject,
      props: { [core + 'parent']: parent, [core + 'isA']: isA, ...values },
      get(k) {
        return this.props[k];
      },
      async set(k, v) {
        this.props[k] = v;
      },
      async save() {},
      async refresh() {},
    };
    rows.set(subject, r);
    return r;
  };
  row('app', 'drive', []);
  row('conversation', 'data', ['conversation']);
  const turn = row('turn', 'conversation', ['turn'], {
    state: 'queued',
    prompt: 'Hello',
    created: 1,
  });
  const store = {
    async getResource(s) {
      return rows.get(s);
    },
    async newResource(o) {
      return row('new' + ++id, o.parent, o.isA, o.propVals);
    },
  };
  const children = async (_s, _d, parent) =>
    [...rows.values()].filter(r => r.get(core + 'parent') === parent);
  class FakeCodex extends EventEmitter {
    requests = [];
    answers = [];
    async initialize() {}
    close() {}
    async request(method, params) {
      this.requests.push({ method, params });
      if (method === 'thread/start' || method === 'thread/resume')
        return { thread: { id: 'thread-one' } };
      if (method === 'turn/start') {
        this.emit('message', {
          method: 'item/commandExecution/requestApproval',
          id: 20,
          params: { threadId: 'thread-one', command: 'pwd' },
        });
        return { turn: { id: 'turn-one' } };
      }
      if (method === 'turn/interrupt') this.finish('interrupted');
      return {};
    }
    send(message) {
      this.answers.push(message);
      if (message.result?.decision === 'accept') this.finish('completed');
    }
    finish(status) {
      this.emit('message', {
        method: 'item/agentMessage/delta',
        params: { threadId: 'thread-one', itemId: 'answer', delta: 'Hello' },
      });
      this.emit('message', {
        method: 'turn/completed',
        params: { threadId: 'thread-one', turn: { id: 'turn-one', status } },
      });
    }
  }
  return { config, rows, row, store, children, codex: new FakeCodex(), turn };
}
async function until(condition) {
  for (let n = 0; n < 300; n++) {
    if (condition()) return;
    await new Promise(r => setTimeout(r, 5));
  }
  throw new Error('Condition timed out');
}
test('approval round trip, fixed workspace, and durable streamed reply', async () => {
  const f = fixture(),
    dir = await mkdtemp(join(tmpdir(), 'codex-chat-')),
    controller = new AbortController();
  const running = work(f.store, f.config, join(dir, 'connection'), {
    ...f,
    signal: controller.signal,
    pollMs: 1,
  });
  try {
    await until(() => [...f.rows.values()].some(r => r.get('request')));
    assert.equal(f.codex.answers.length, 0);
    const approval = [...f.rows.values()].find(r => r.get('request'));
    await approval.set('answer', 'accept');
    await until(() => f.turn.get('state') === 'completed');
    assert.equal(f.turn.get('transcript')[0].text, 'Hello');
    assert.equal(f.codex.answers[0].result.decision, 'accept');
    const start = f.codex.requests.find(x => x.method === 'thread/start');
    assert.equal(start.params.cwd, '/fixed/workspace');
    assert.equal(start.params.sandbox, 'read-only');
    assert.equal(start.params.approvalsReviewer, 'user');
    assert.deepEqual(
      JSON.parse(await readFile(join(dir, 'connection.journal'), 'utf8')).seen,
      ['turn'],
    );
  } finally {
    controller.abort();
    await running;
    await rm(dir, { recursive: true, force: true });
  }
});
test('Stop interrupts the active turn', async () => {
  const f = fixture(),
    dir = await mkdtemp(join(tmpdir(), 'codex-chat-')),
    controller = new AbortController();
  const running = work(f.store, f.config, join(dir, 'connection'), {
    ...f,
    signal: controller.signal,
    pollMs: 1,
  });
  try {
    await until(() => f.codex.requests.some(x => x.method === 'turn/start'));
    f.row('stop', 'turn', [], { cancel: true });
    await until(() => f.turn.get('state') === 'interrupted');
    assert.ok(f.codex.requests.some(x => x.method === 'turn/interrupt'));
  } finally {
    controller.abort();
    await running;
    await rm(dir, { recursive: true, force: true });
  }
});
test('restart never replays a claimed prompt, including before running was saved', async () => {
  const f = fixture(),
    dir = await mkdtemp(join(tmpdir(), 'codex-chat-')),
    file = join(dir, 'connection'),
    controller = new AbortController();
  await writeFile(
    file + '.journal',
    JSON.stringify({ seen: ['turn'], threads: {} }),
  );
  const running = work(f.store, f.config, file, {
    ...f,
    signal: controller.signal,
    pollMs: 1,
  });
  try {
    await until(() => f.turn.get('state') === 'uncertain');
    assert.equal(f.codex.requests.length, 0);
  } finally {
    controller.abort();
    await running;
    await rm(dir, { recursive: true, force: true });
  }
});
