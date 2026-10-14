import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { Store } from '@tomic/lib';

const state = vi.hoisted(() => ({
  keyless: false,
  seeded: [] as string[][],
  workers: [] as {
    ready: PromiseWithResolvers<void>;
    barrier: PromiseWithResolvers<void>;
  }[],
}));
vi.mock('@tomic/lib', () => ({
  StoreEvents: { AgentChanged: 'agent' },
  perfSpan: () => () => {},
  ClientDbWorker: class {
    ready = Promise.withResolvers<void>();
    barrier = Promise.withResolvers<void>();
    initError = undefined;
    constructor() {
      state.workers.push(this);
    }
    init() {
      return this.ready.promise;
    }
    setSeedPromise() {}
    waitForReady() {
      return this.ready.promise.then(() => true);
    }
    flush() {
      return this.barrier.promise;
    }
    allSubjects() {
      return Promise.resolve([]);
    }
    putResources(resources: string[]) {
      state.seeded.push(resources);

      return Promise.resolve();
    }
    destroy() {}
  },
}));
vi.mock('@tomic/lib/client-db.worker.js?url', () => ({ default: 'worker.js' }));
vi.mock('./wasmUrls', () => ({
  wasmJsUrl: () => 'wasm.js',
  compiledAtomicWasm: async () => undefined,
}));
vi.mock('./localDbKey', () => ({
  agentDbFingerprint: async () => 'agent',
  getSessionDbKey: async () =>
    state.keyless ? undefined : new Uint8Array(32),
  hasWrappedDbKey: async () => state.keyless,
  waitForSessionDbKey: async () => undefined,
  getOrCreateSessionDbKey: async () => new Uint8Array(32),
}));
beforeEach(() => {
  vi.resetModules();
  state.workers.splice(0);
  state.seeded.splice(0);
});
afterEach(() => vi.unstubAllGlobals());
it('an anonymous worker finishing initialization cannot reattach after sign-in', async () => {
  vi.stubGlobal('Worker', class {});
  let agent: { subject: string } | undefined;
  let listener: (next: { subject: string } | undefined) => void = () => {};
  let attached: unknown;
  const store = {
    expectClientDb() {},
    clientDbUnavailable() {},
    clientDbDeferred() {},
    getAgent: () => agent,
    on: (_: string, callback: typeof listener) => {
      listener = callback;

      return () => {};
    },
    getServerUrl: () => 'http://localhost',
    resources: new Map(),
    setClientDb: vi.fn((db: unknown) => {
      attached = db;
    }),
    notifyError: vi.fn(),
  };
  const { initClientDb } = await import('./initClientDb');
  initClientDb(store as unknown as Store);
  await vi.waitFor(() => expect(state.workers).toHaveLength(1));
  const anonymous = state.workers[0];
  expect(attached).toBe(anonymous);
  agent = { subject: 'did:ad:agent:new' };
  listener(agent);
  expect(attached).toBeUndefined();
  await new Promise(resolve => setTimeout(resolve, 0));
  agent = { subject: 'did:ad:agent:newer' };
  listener(agent);
  anonymous.ready.resolve();
  // Let initialization finish while the old worker's final flush is pending.
  await new Promise(resolve => setTimeout(resolve, 20));
  expect(attached).toBeUndefined();
  anonymous.barrier.resolve();
  await vi.waitFor(() => expect(state.workers).toHaveLength(2));
  expect(attached).toBe(state.workers[1]);
  state.workers[1].ready.resolve();
  state.workers[1].barrier.resolve();
  await new Promise(resolve => setTimeout(resolve, 20));
  expect(state.workers).toHaveLength(2);
});

it('dev-drive setup can defer the anonymous worker and initialize only its fresh identity', async () => {
  vi.stubGlobal('Worker', class {});
  let agent: { subject: string } | undefined;
  let listener: (next: { subject: string } | undefined) => void = () => {};
  const store = {
    expectClientDb: vi.fn(),
    clientDbUnavailable: vi.fn(),
    clientDbDeferred: vi.fn(),
    getAgent: () => agent,
    on: (_: string, callback: typeof listener) => {
      listener = callback;

      return () => {};
    },
    getServerUrl: () => 'http://localhost',
    resources: new Map(),
    setClientDb: vi.fn(),
    notifyError: vi.fn(),
  };
  const { initClientDb } = await import('./initClientDb');
  initClientDb(store as unknown as Store, { deferAnonymous: true });
  await Promise.resolve();
  expect(store.expectClientDb).toHaveBeenCalled();
  expect(state.workers).toHaveLength(0);
  agent = { subject: 'did:ad:agent:fresh-test' };
  store.expectClientDb.mockClear();
  listener(agent);
  // Synchronously, before the serialized start runs: reads triggered by this
  // sign-in must wait for the attach rather than fail as offline.
  expect(store.expectClientDb).toHaveBeenCalledTimes(1);
  await vi.waitFor(() => expect(state.workers).toHaveLength(1));
  expect(store.setClientDb).toHaveBeenLastCalledWith(state.workers[0]);
  state.workers[0].ready.resolve();
  state.workers[0].barrier.resolve();
  await new Promise(resolve => setTimeout(resolve, 0));
  expect(state.seeded).toEqual([]);
});

it('a start with no usable key defers the database instead of declaring it unavailable', async () => {
  vi.stubGlobal('Worker', class {});
  state.keyless = true;
  let agent: { subject: string } | undefined;
  let listener: (next: { subject: string } | undefined) => void = () => {};
  const store = {
    expectClientDb: vi.fn(),
    clientDbUnavailable: vi.fn(),
    clientDbDeferred: vi.fn(),
    getAgent: () => agent,
    on: (_: string, callback: typeof listener) => {
      listener = callback;

      return () => {};
    },
    getServerUrl: () => 'http://localhost',
    resources: new Map(),
    setClientDb: vi.fn(),
    notifyError: vi.fn(),
  };
  try {
    const { initClientDb } = await import('./initClientDb');
    initClientDb(store as unknown as Store, { deferAnonymous: true });
    agent = { subject: 'did:ad:agent:wrapped' };
    listener(agent);
    await vi.waitFor(() => expect(store.clientDbDeferred).toHaveBeenCalled());
    // A sign-in will still deliver the key, so sync and server deliveries
    // must keep treating the database as expected.
    expect(store.clientDbUnavailable).not.toHaveBeenCalled();
    expect(state.workers).toHaveLength(0);
  } finally {
    state.keyless = false;
  }
});
