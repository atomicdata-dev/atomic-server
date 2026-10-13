import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { readConfig, credentialFor, openAtomic } from './atomic.mjs';

const script = fileURLToPath(new URL('./atomic.mjs', import.meta.url));
const agent = 'atomic:agent:invented-public-agent';
const drive = 'atomic:invented-drive';
const metadata = {
  serverUrl: 'http://localhost:9883',
  agent,
  drive,
  library: 'library.mjs',
  documentReader: 'reader.mjs',
  documentWriter: 'writer.mjs',
  credentialCommand: {
    command: process.execPath,
    args: ['-e', "process.stdout.write('fixture-secret')"],
  },
};
async function fixture(t, overrides = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'atomic-drive-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const configPath = join(dir, 'bootstrap.json');
  await writeFile(configPath, JSON.stringify({ ...metadata, ...overrides }));
  return { dir, configPath };
}
async function fakeRuntime(dir, mode = 'success') {
  await writeFile(
    join(dir, 'library.mjs'),
    `
export class Agent {static async fromSecret(secret) {
 if(secret !== 'fixture-secret') throw new Error('Never print: '+secret);
 return {subject: '${agent.replace('atomic:', 'did:ad:')}' };
}}
export async function enableLoro() {}
export class Store {
 constructor(config) {this.config=config;}
 setServerConnected() {}
 injectFetch(fetcher) {this.fetcher=fetcher;}
 async fetchResourceFromServer(subject, opts) {
  if(opts.noWebSocket !== true) throw new Error('Unexpected subscription');
  return {subject, error: ${mode === 'error' ? "new Error('Synthetic read failure')" : 'undefined'},
   get: () => '${drive}', hasClasses: () => false};
 }
 getSyncStatus() {return {pendingDirtyCount: 0, blockedCount: 0};}
 disconnect() {}
}
export async function readResourceCompact(store, subject) {return {'@id': subject, endpoint: store.config.serverUrl};}
export async function createResourceFromCompact() {return {subject:'atomic:created'};}
export async function setResourceProperty() {return {subject:'atomic:edited'};}
export const dataBrowser={classes:{documentV2:'atomic:document',meeting:'atomic:meeting'}};
`,
  );
  await writeFile(
    join(dir, 'reader.mjs'),
    'export function documentText(){return "";}',
  );
  await writeFile(
    join(dir, 'writer.mjs'),
    'export function writeDocumentText(){}',
  );
}

for (const endpoint of [
  'http://localhost:11870',
  'http://127.0.0.1:12000',
  'http://[::1]:9883',
  'https://atomic.example.org:8443',
])
  test(`configurable endpoint ${endpoint}`, async t => {
    const { dir, configPath } = await fixture(t, { serverUrl: endpoint });
    const config = await readConfig(configPath);
    assert.equal(config.serverUrl, endpoint);
    assert.equal(config.library, join(dir, 'library.mjs'));
  });
for (const endpoint of [
  'http://atomic.example.org',
  'https://user:secret@atomic.example.org',
  'https://atomic.example.org/path',
  'https://atomic.example.org/?key=secret',
  'https://atomic.example.org/#fragment',
  'file:///tmp/drive',
  'http://localhost.example.org',
])
  test(`reject malformed or unsafe origin ${endpoint}`, async t => {
    const { configPath } = await fixture(t, { serverUrl: endpoint });
    await assert.rejects(readConfig(configPath));
  });
test('explicit URL environment override retains public identity', async t => {
  const { configPath } = await fixture(t);
  const before = process.env.ATOMIC_SERVER_URL;
  t.after(() => {
    if (before === undefined) delete process.env.ATOMIC_SERVER_URL;
    else process.env.ATOMIC_SERVER_URL = before;
  });
  process.env.ATOMIC_SERVER_URL = 'https://another.example.org';
  assert.equal(
    (await readConfig(configPath)).serverUrl,
    'https://another.example.org',
  );
});
test('credential command receives only public arguments and its output stays internal', () => {
  const config = {
    agent,
    credentialCommand: {
      command: process.execPath,
      args: [
        '-e',
        "if(process.argv[1] !== '" +
          agent +
          "')process.exit(2); process.stdout.write('fixture-secret\\n')",
      ],
    },
  };
  assert.deepEqual(credentialFor(config), { secret: 'fixture-secret' });
});
test('credential errors never include stdout or stderr', () => {
  assert.throws(
    () =>
      credentialFor({
        agent,
        credentialCommand: {
          command: process.execPath,
          args: [
            '-e',
            "process.stdout.write('fixture-secret'); process.stderr.write('fixture-secret'); process.exit(2)",
          ],
        },
      }),
    error =>
      error.message === 'Credential command failed or returned no credential.',
  );
});
test('supports a secret-injected environment and rejects mixed credential sources', async t => {
  const name = 'ATOMIC_DRIVE_TEST_SECRET';
  process.env[name] = 'fixture-secret';
  t.after(() => delete process.env[name]);
  assert.deepEqual(credentialFor({ credentialEnv: name }), {
    secret: 'fixture-secret',
  });
  const { configPath } = await fixture(t, { credentialEnv: name });
  await assert.rejects(readConfig(configPath), /Select one/);
});
test('HTTP bootstrap reads through compatible SDK without opening a subscription', async t => {
  const { dir, configPath } = await fixture(t);
  await fakeRuntime(dir);
  const a = await openAtomic(configPath);
  t.after(() => a.store.disconnect());
  assert.deepEqual(await a.read('atomic:invented-resource'), {
    '@id': 'atomic:invented-resource',
    endpoint: metadata.serverUrl,
  });
  assert.equal(a.store.config.connect, false);
  assert.equal(a.store.config.requireOnlineWrites, true);
});
test('failed reads propagate, without falling back to unrelated state', async t => {
  const { dir, configPath } = await fixture(t);
  await fakeRuntime(dir, 'error');
  const a = await openAtomic(configPath);
  t.after(() => a.store.disconnect());
  await assert.rejects(
    a.read('atomic:invented-resource'),
    /Synthetic read failure/,
  );
});
test('incompatible runtime fails before invoking credential command', async t => {
  const { dir, configPath } = await fixture(t, {
    credentialCommand: { command: 'nonexistent-credential-helper', args: [] },
  });
  await writeFile(join(dir, 'library.mjs'), 'export const Agent={};');
  await assert.rejects(openAtomic(configPath), /Incompatible Atomic library/);
});
test('CLI identity prints no secret and invalid secret errors are redacted', async t => {
  const { dir, configPath } = await fixture(t);
  await fakeRuntime(dir);
  const env = { ...process.env, ATOMIC_BOOTSTRAP_CONFIG: configPath };
  const result = spawnSync(process.execPath, [script, 'identity'], {
    env,
    encoding: 'utf8',
  });
  assert.equal(result.status, 0);
  assert.equal(JSON.parse(result.stdout).agent, agent);
  assert.ok(!(result.stdout + result.stderr).includes('fixture-secret'));
  await writeFile(
    configPath,
    JSON.stringify({
      ...metadata,
      credentialCommand: {
        command: process.execPath,
        args: ['-e', "process.stdout.write('invalid-fixture-secret')"],
      },
    }),
  );
  const invalid = spawnSync(process.execPath, [script, 'identity'], {
    env,
    encoding: 'utf8',
  });
  assert.equal(invalid.status, 1);
  assert.ok(!invalid.stderr.includes('invalid-fixture-secret'));
});
test('registry scope prevents loading a document from another drive', async t => {
  const { dir, configPath } = await fixture(t, {
    drive: 'atomic:another-drive',
    registry: 'atomic:registry',
  });
  await fakeRuntime(dir);
  const a = await openAtomic(configPath);
  t.after(() => a.store.disconnect());
  await assert.rejects(a.registry(), /Registry content must belong/);
});

test('environment-mode run refuses before fetching or caching registry code', async t => {
  const { dir, configPath } = await fixture(t, {
    credentialCommand: undefined,
    credentialEnv: 'ATOMIC_DRIVE_TEST_SECRET',
  });
  await fakeRuntime(dir);
  const result = spawnSync(
    process.execPath,
    [script, 'run', 'invented', 'script.mjs'],
    {
      encoding: 'utf8',
      env: {
        ...process.env,
        ATOMIC_BOOTSTRAP_CONFIG: configPath,
        ATOMIC_DRIVE_TEST_SECRET: 'fixture-secret',
      },
    },
  );
  assert.equal(result.status, 1);
  assert.match(result.stderr, /environment credentials are not forwarded/);
  assert.ok(!result.stderr.includes('fixture-secret'));
  assert.ok(!(await readdir(dir)).includes('script-cache'));
});
