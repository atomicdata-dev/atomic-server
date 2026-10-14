import { beforeEach, expect, it, vi } from 'vitest';
import type { Store } from '@tomic/lib';

const state = vi.hoisted(() => ({
  batches: [] as string[][],
  withSnapshot: [] as { subject: string; jsonAd: string; snapshot: unknown }[],
  workers: [] as { ready: PromiseWithResolvers<void> }[],
}));
vi.mock('@tomic/lib', () => ({
  StoreEvents: { AgentChanged: 'agent' },
  perfSpan: () => () => {},
  ClientDbWorker: class {
    ready = Promise.withResolvers<void>();
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
      return Promise.resolve();
    }
    allSubjects() {
      return Promise.resolve([]);
    }
    putResources(resources: string[]) {
      state.batches.push(resources);

      return Promise.resolve();
    }
    putResourceWithSnapshot(
      subject: string,
      jsonAd: string,
      snapshot: unknown,
    ) {
      state.withSnapshot.push({ subject, jsonAd, snapshot });

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
  getSessionDbKey: async () => new Uint8Array(32),
  hasWrappedDbKey: async () => false,
  getOrCreateSessionDbKey: async () => new Uint8Array(32),
}));

beforeEach(() => {
  vi.resetModules();
  state.batches.splice(0);
  state.withSnapshot.splice(0);
  state.workers.splice(0);
});

const IS_A = 'https://atomicdata.dev/properties/isA';

function fakeResource(
  subject: string,
  props: Record<string, unknown>,
  history?: Uint8Array,
) {
  return {
    subject,
    loading: false,
    new: false,
    hasPendingCommits: false,
    get: (prop: string) => props[prop],
    getEntries: () => Object.entries(props),
    hasLoroDoc: () => !!history,
    getLoroDoc: () =>
      history && {
        oplogVersion: () => ({ toJSON: () => new Map([['7', 24]]) }),
        export: () => history,
      },
  };
}

it('seeds a resource that has Loro history with its snapshot, not rebuilt from propvals', async () => {
  vi.stubGlobal('Worker', class {});
  // Rebuilt from its propvals, this document would get a fresh peer id: same
  // values, but a version vector the server reads as ahead of its own, so the
  // next drive reconcile asks this tab to push it.
  const history = new Uint8Array([1, 2, 3]);
  const ontology = fakeResource(
    'atomic:ontology',
    { [IS_A]: ['https://atomicdata.dev/class/ontology'], name: 'o' },
    history,
  );
  const property = fakeResource('https://example.com/p', {
    [IS_A]: ['https://atomicdata.dev/classes/Property'],
    shortname: 'p',
  });
  const store = {
    expectClientDb() {},
    getAgent: () => undefined,
    on: () => () => {},
    getServerUrl: () => 'http://localhost',
    resources: new Map<string, unknown>([
      [ontology.subject, ontology],
      [property.subject, property],
    ]),
    setClientDb: vi.fn(),
    notifyError: vi.fn(),
  };
  const { initClientDb } = await import('./initClientDb');
  initClientDb(store as unknown as Store);
  await vi.waitFor(() => expect(state.workers).toHaveLength(1));
  state.workers[0].ready.resolve();

  await vi.waitFor(() => expect(state.withSnapshot).toHaveLength(1));
  expect(state.withSnapshot[0].subject).toBe('atomic:ontology');
  expect(state.withSnapshot[0].snapshot).toBe(history);
  expect(JSON.parse(state.withSnapshot[0].jsonAd)['@id']).toBe(
    'atomic:ontology',
  );

  // Resources without a history still go in one batch, and the one with a
  // history is not also written without its snapshot.
  const batched = state.batches.flat().map(json => JSON.parse(json)['@id']);
  expect(batched).toEqual(['https://example.com/p']);
});
