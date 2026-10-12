import { afterEach, describe, expect, it, vi } from 'vitest';
import { CollectionBuilder } from './collectionBuilder.js';
import { Store } from './store.js';
import { core } from './ontologies/core.js';
import { collections } from './ontologies/collections.js';
import type { ClientDbWorker } from './client-db.js';

/**
 * A device opening a large drive syncs it into its local database, and that
 * sync keeps the database's worker busy. A collection query queued behind it
 * held the sidebar empty while the server, which has the whole drive, could
 * have answered in milliseconds.
 */
const HOME = 'https://app.example.com';
const DRIVE = 'did:ad:drive';
const ROW = 'did:ad:row';

function setup(query: ClientDbWorker['query']) {
  const store = new Store({ serverUrl: HOME, connect: false });
  store.setClientDb({
    isReady: true,
    waitForReady: async () => true,
    query,
  } as unknown as ClientDbWorker);
  const requests: URL[] = [];
  store.injectFetch(async input => {
    const url = new URL(String(input));
    requests.push(url);

    return new Response(
      JSON.stringify({
        '@id': url.href,
        [collections.properties.members]: [ROW],
        [collections.properties.totalMembers]: 1,
      }),
      { status: 200 },
    );
  });
  store.setDrive(DRIVE);
  store.setServerConnected(true);
  store.startDriveSync();

  return { store, requests };
}

function childrenOf(store: Store) {
  return new CollectionBuilder(store)
    .setProperty(core.properties.parent)
    .setValue(DRIVE)
    .buildAndFetch();
}

afterEach(() => {
  vi.useRealTimers();
});

describe('a collection query while the drive syncs', () => {
  it('asks the server when the busy local database does not answer', async () => {
    const query = vi.fn(() => new Promise<never>(() => undefined));
    const { store, requests } = setup(query);
    vi.useFakeTimers();

    const pending = childrenOf(store);
    await vi.advanceTimersByTimeAsync(200);
    const collection = await pending;

    expect(query).toHaveBeenCalled();
    expect(requests.length).toBeGreaterThan(0);
    expect(await collection.getMemberWithIndex(0)).toBe(ROW);
  });

  it('does not queue a local query while the sync is pulling', async () => {
    const query = vi.fn(async () => ({ subjects: [], count: 0 }));
    const { store, requests } = setup(query);
    store.startDriveSyncPull();

    await childrenOf(store);

    expect(query).not.toHaveBeenCalled();
    expect(requests.length).toBeGreaterThan(0);
  });
});
