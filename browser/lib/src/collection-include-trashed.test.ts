import { describe, it } from 'vitest';
import { Collection, CollectionParams } from './collection.js';
import { buildSearchSubject } from './search.js';
import { Store } from './store.js';
import type {
  ClientDbQueryOpts,
  ClientDbQueryResult,
  ClientDbWorker,
} from './client-db.js';
import { core, dataBrowser } from './index.js';

/**
 * The server hides trashed members unless `include_trashed=true`. The local
 * WASM query must make the same choice or counts and pages disagree.
 */
function fakeClientDb(): {
  clientDb: ClientDbWorker;
  calls: ClientDbQueryOpts[];
} {
  const calls: ClientDbQueryOpts[] = [];
  const stub = {
    isReady: true,
    waitForReady: async () => true,
    query: async (opts: ClientDbQueryOpts): Promise<ClientDbQueryResult> => {
      calls.push(opts);

      return { subjects: [], resources: [], count: 0 };
    },
  };

  return { clientDb: stub as unknown as ClientDbWorker, calls };
}

const params = (extra: Partial<CollectionParams> = {}): CollectionParams => ({
  page_size: '30',
  include_nested: false,
  property: core.properties.parent,
  value: 'did:ad:drive:test',
  filters: [
    { property: core.properties.isA, value: dataBrowser.classes.message },
  ],
  drive: 'did:ad:drive:test',
  ...extra,
});

async function localCalls(
  extra: Partial<CollectionParams>,
): Promise<ClientDbQueryOpts[]> {
  const store = new Store({ serverUrl: 'https://example.com' });
  const { clientDb, calls } = fakeClientDb();
  store.setClientDb(clientDb);
  store.setDrive('did:ad:drive:test');
  const collection = new Collection(
    store,
    'https://example.com',
    params(extra),
  );
  await collection.waitForReady();

  return calls;
}

describe('include_trashed', () => {
  it('hides trashed members locally by default', async ({ expect }) => {
    const calls = await localCalls({});

    expect(calls.length).toBeGreaterThan(0);
    expect(calls.every(c => !c.includeTrashed)).toBe(true);
  });

  it('forwards include_trashed to the local query', async ({ expect }) => {
    const calls = await localCalls({ include_trashed: true });

    expect(calls.length).toBeGreaterThan(0);
    expect(calls.every(c => c.includeTrashed === true)).toBe(true);
  });

  it('puts include_trashed on the server URL only when set', ({ expect }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    const url = (extra: Partial<CollectionParams>) =>
      new URL(
        new Collection(store, 'https://example.com', params(extra))[
          'buildSubject'
        ](0),
      );

    expect(url({}).searchParams.has('include_trashed')).toBe(false);
    expect(
      url({ include_trashed: true }).searchParams.get('include_trashed'),
    ).toBe('true');
  });

  it('adds include_trashed to the search URL only when set', ({ expect }) => {
    const base = buildSearchSubject('https://example.com', 'x');
    const on = buildSearchSubject('https://example.com', 'x', {
      includeTrashed: true,
    });

    expect(new URL(base).searchParams.has('include_trashed')).toBe(false);
    expect(new URL(on).searchParams.get('include_trashed')).toBe('true');
  });
});
