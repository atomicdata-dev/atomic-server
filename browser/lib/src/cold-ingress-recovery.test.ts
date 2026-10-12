import { beforeAll, expect, it, vi } from 'vitest';
import { LoroLoader } from './loro-loader.js';
import { Store } from './store.js';
import { attachTestDb } from './test-store.js';
import { core } from './ontologies/core.js';
import { Agent } from './agent.js';
import { JSCryptoProvider } from './CryptoProvider.js';

beforeAll(() => LoroLoader.initializeLoro());

function fixture() {
  const store = new Store({ serverUrl: 'http://localhost', connect: false });
  const { records } = attachTestDb(store);
  const subject = 'atomic:cold-ingress';
  const base = new LoroLoader.Loro.LoroDoc();
  base.getMap('properties').set(core.properties.name, 'before');
  const snapshot = base.export({ mode: 'snapshot' });
  const local = new LoroLoader.Loro.LoroDoc();
  local.import(snapshot);
  local.getMap('properties').set(core.properties.name, 'acknowledged offline');
  const remote = new LoroLoader.Loro.LoroDoc();
  remote.import(snapshot);
  remote.getMap('properties').set(core.properties.description, 'remote edit');
  records.set(subject, {
    jsonAd: JSON.stringify({
      '@id': subject,
      [core.properties.name]: 'acknowledged offline',
    }),
    snapshot: local.export({ mode: 'snapshot' }),
  });
  const change = {
    subject,
    loroBytes: remote.export({ mode: 'snapshot' }),
    source: 'ws-sync-push' as const,
  };

  return { store, records, subject, snapshot, change };
}

it.each([false, true])(
  'merges remote state with an unmounted durable edit (full replacement requested: %s)',
  async replace => {
    const { store, records, subject, change } = fixture();
    expect(store.outbox.hasPending(subject)).toBe(false);
    expect(store.resources.has(subject)).toBe(false);
    await store.applyRemoteIncoming({
      ...change,
      replaceLoroDocsFromRemote: replace,
    });
    expect(store.resources.get(subject)?.get(core.properties.name)).toBe(
      'acknowledged offline',
    );
    expect(store.resources.get(subject)?.get(core.properties.description)).toBe(
      'remote edit',
    );
    expect(JSON.parse(records.get(subject)!.jsonAd)[core.properties.name]).toBe(
      'acknowledged offline',
    );
  },
);

it('does not replace local data when reading its snapshot fails', async () => {
  const { store, records, subject, change } = fixture();
  vi.spyOn(store.getClientDb()!, 'getResourceWithSnapshot').mockRejectedValue(
    new Error('storage read failed'),
  );
  await expect(store.applyRemoteIncoming(change)).rejects.toThrow(
    'storage read failed',
  );
  expect(store.resources.has(subject)).toBe(false);
  expect(JSON.parse(records.get(subject)!.jsonAd)[core.properties.name]).toBe(
    'acknowledged offline',
  );
});

it.each(['database', 'connection', 'removal'])(
  'rejects a remote update when %s invalidates its local read',
  async replaced => {
    const { store, records, subject, change } = fixture();
    let release!: () => void;
    let entered!: () => void;
    const gate = new Promise<void>(resolve => {
      release = resolve;
    });
    const reading = new Promise<void>(resolve => {
      entered = resolve;
    });
    vi.spyOn(
      store.getClientDb()!,
      'getResourceWithSnapshot',
    ).mockImplementation(async () => {
      const result = {
        jsonAd: records.get(subject)!.jsonAd,
        snapshot: records.get(subject)!.snapshot!,
      };
      entered();
      await gate;

      return result;
    });
    let current = true;
    const work = store.applyRemoteIncoming(change, () => current);
    const rejected = expect(work).rejects.toThrow('database changed');
    await reading;
    if (replaced === 'database') store.setClientDb(undefined);
    else if (replaced === 'removal') store.removeResource(subject);
    else current = false;
    release();
    await rejected;
    expect(store.resources.has(subject)).toBe(false);
  },
);

it('serializes simultaneous remote arrivals without dropping either change', async () => {
  const { store, records, subject, snapshot, change } = fixture();
  const other = new LoroLoader.Loro.LoroDoc();
  other.import(snapshot);
  other.getMap('properties').set('https://example.test/flag', true);
  await Promise.all([
    store.applyRemoteIncoming(change),
    store.applyRemoteIncoming({
      ...change,
      loroBytes: other.export({ mode: 'snapshot' }),
    }),
  ]);
  const stored = JSON.parse(records.get(subject)!.jsonAd);
  expect(stored[core.properties.name]).toBe('acknowledged offline');
  expect(stored[core.properties.description]).toBe('remote edit');
  expect(stored['https://example.test/flag']).toBe(true);
});

it.each([false, true])(
  'awaits durable incoming persistence (fails: %s)',
  async fails => {
    const { store, subject, change } = fixture();
    let release!: () => void;
    const gate = new Promise<void>(resolve => {
      release = resolve;
    });
    vi.spyOn(
      store.getClientDb()!,
      'putResourceWithSnapshot',
    ).mockImplementation(async () => {
      await gate;
      if (fails) throw new Error('durable put failed');
    });
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    let settled = false;
    const work = store.applyRemoteIncoming(change);
    void work.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    await vi.waitFor(() => expect(store.resources.has(subject)).toBe(true));
    expect(settled).toBe(false);
    release();
    if (fails) await expect(work).rejects.toThrow('durable put failed');
    else await expect(work).resolves.toBe('applied');
    logged.mockRestore();
  },
);

it.each([
  ['an equal agent with the same subject', true],
  ['a different agent', false],
])('a read in flight survives %s replacing the agent: %s', async (_, same) => {
  const { store, records, subject, change } = fixture();
  const keys = await Agent.generateKeyPair();
  const agent = new Agent(
    new JSCryptoProvider(keys.privateKey),
    `did:ad:agent:${keys.publicKey}`,
  );
  store.setAgent(agent);
  let release!: () => void;
  let entered!: () => void;
  const gate = new Promise<void>(resolve => {
    release = resolve;
  });
  const reading = new Promise<void>(resolve => {
    entered = resolve;
  });
  vi.spyOn(store.getClientDb()!, 'getResourceWithSnapshot').mockImplementation(
    async () => {
      const result = {
        jsonAd: records.get(subject)!.jsonAd,
        snapshot: records.get(subject)!.snapshot!,
      };
      entered();
      await gate;

      return result;
    },
  );
  const work = store.applyRemoteIncoming(change);
  const outcome = same
    ? expect(work).resolves.toBe('applied')
    : expect(work).rejects.toThrow('database changed');
  await reading;

  if (same) {
    store.setAgent(
      new Agent(new JSCryptoProvider(keys.privateKey), agent.subject),
    );
  } else {
    const other = await Agent.generateKeyPair();
    store.setAgent(
      new Agent(
        new JSCryptoProvider(other.privateKey),
        `did:ad:agent:${other.publicKey}`,
      ),
    );
  }

  release();
  await outcome;
});
