import { describe, it } from 'vitest';
import { Collection } from './collection.js';
import type { ClientDbQueryResult, ClientDbWorker } from './client-db.js';
import { core } from './index.js';
import { Store } from './store.js';

/**
 * When the local WASM DB answers a collection query with zero rows, that is
 * only meaningful if the drive in question has actually been synced into it.
 * An unsynced drive's index is empty because nothing put anything there, not
 * because the drive has no children.
 *
 * The distinction used to be made with "has ANY drive sync finished this
 * session", which is a different question. Signing in provisions and syncs the
 * user's own (new, tiny) personal drive; that flipped the flag, and from then
 * on an empty local result for ANY other drive was believed. Browsing a large
 * drive that had never been synced locally therefore showed an empty sidebar
 * while signed in, and a full one while signed out — because signed out there
 * is no local DB and the query goes to the server.
 */
describe('empty local-DB results are only trusted for synced drives', () => {
  const DRIVE_A = 'did:ad:resource:drive-a';
  const DRIVE_B = 'did:ad:resource:drive-b';

  it('does not vouch for a drive before any sync', ({ expect }) => {
    const store = new Store({ serverUrl: 'https://example.com' });

    expect(store.hasCompletedDriveSyncFor(DRIVE_A)).toBe(false);
  });

  it('vouches for a drive once its own sync finishes', ({ expect }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    store.finishDriveSync(DRIVE_A, 12, Date.now());

    expect(store.hasCompletedDriveSyncFor(DRIVE_A)).toBe(true);
  });

  it('does NOT let one synced drive vouch for another', ({ expect }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    store.finishDriveSync(DRIVE_A, 12, Date.now());

    // The regression: syncing the personal drive must not make an empty
    // result for an unrelated, never-synced drive look authoritative.
    expect(store.hasCompletedDriveSyncFor(DRIVE_B)).toBe(false);
  });

  it('remembers every synced drive, not only the most recent', ({ expect }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    store.finishDriveSync(DRIVE_A, 12, Date.now());
    store.finishDriveSync(DRIVE_B, 3, Date.now());

    expect(store.hasCompletedDriveSyncFor(DRIVE_A)).toBe(true);
    expect(store.hasCompletedDriveSyncFor(DRIVE_B)).toBe(true);
  });

  it('treats an unknown drive as unsynced, so the caller asks the server', ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    store.finishDriveSync(DRIVE_A, 12, Date.now());

    expect(store.hasCompletedDriveSyncFor(undefined)).toBe(false);
  });
});

describe('an empty matching set still carries its statistics', () => {
  it('exposes count=0 rather than leaving aggregates unset', async ({
    expect,
  }) => {
    const drive = 'did:ad:resource:drive-a';
    const store = new Store({ serverUrl: 'https://example.com' });
    store.setDrive(drive);
    store.finishDriveSync(drive, 1, Date.now());
    store.setClientDb({
      isReady: true,
      waitForReady: async () => true,
      query: async (): Promise<ClientDbQueryResult> => ({
        subjects: [],
        resources: [],
        count: 0,
        aggregates: [{ id: 'block', function: 'count', value: 0, count: 0 }],
      }),
    } as unknown as ClientDbWorker);

    const collection = new Collection(store, 'https://example.com', {
      page_size: '1',
      include_nested: false,
      property: core.properties.parent,
      value: 'did:ad:resource:table',
      drive,
      aggregation: { aggregates: [{ id: 'block', function: 'count' }] },
    });
    await collection.waitForReady();

    expect(collection.aggregates).toEqual([
      { id: 'block', function: 'count', value: 0, count: 0 },
    ]);
  });
});

/**
 * Cold load: the local DB has an OPFS file but nothing indexed for this
 * parent yet, and the WebSocket hasn't finished its handshake. Signing in
 * makes that window wider — `serverConnected` only flips after AUTH_OK — so
 * the sidebar's first (and, for a server-root drive, only) query landed in it
 * every time. The page must not resolve empty and stay that way: nothing
 * re-queries a collection on reconnect, so an empty here is permanent for the
 * session, rendered without a loader or an error.
 */
describe('a query that outruns the WebSocket handshake', () => {
  const unpopulatedClientDb = () =>
    ({
      isReady: true,
      waitForReady: async () => true,
      query: async (): Promise<ClientDbQueryResult> => ({
        subjects: [],
        resources: [],
        count: 0,
        aggregates: [],
      }),
    }) as unknown as ClientDbWorker;

  it('waits for the connection instead of resolving an empty page', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    // Every server fetch fails; we only care that one is attempted at all.
    store.injectFetch(async () => {
      throw new Error('offline');
    });
    store.setClientDb(unpopulatedClientDb());

    const collection = new Collection(store, 'https://example.com', {
      page_size: '30',
      include_nested: false,
      property: core.properties.parent,
      value: 'https://example.com',
    });

    let resolved = false;
    const ready = collection.waitForReady().then(() => {
      resolved = true;
    });

    await new Promise(resolve => setTimeout(resolve, 50));
    expect(resolved).toBe(false);

    store.setServerConnected(true);
    await ready;

    expect(resolved).toBe(true);
  });
});
