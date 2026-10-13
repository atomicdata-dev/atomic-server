import { describe, expect, it, vi } from 'vitest';
import { CollectionBuilder } from './collectionBuilder.js';
import { Store } from './store.js';
import { core } from './ontologies/core.js';
import { collections } from './ontologies/collections.js';
import type { ClientDbWorker } from './client-db.js';

/**
 * A non-empty local answer is only the whole answer for a drive this client
 * has synced. A guest in a chatroom shared from someone else's drive never
 * syncs that drive: their local database holds their own messages and the
 * ones that were there when they joined. Trusting it hid every later message
 * from the host, and a reload asked the same local database again.
 */
const HOME = 'https://app.example.com';
const OWN_DRIVE = 'did:ad:own-drive';
const HOST_DRIVE = 'did:ad:host-drive';
const ROOM = 'did:ad:room';
const MINE = 'did:ad:my-message';
const THEIRS = 'did:ad:their-message';

function setup() {
  const store = new Store({ serverUrl: HOME, connect: false });
  store.setClientDb({
    isReady: true,
    waitForReady: async () => true,
    query: vi.fn(async () => ({ subjects: [MINE], count: 1 })),
  } as unknown as ClientDbWorker);
  const requests: URL[] = [];
  store.injectFetch(async input => {
    const url = new URL(String(input));
    requests.push(url);

    return new Response(
      JSON.stringify({
        '@id': url.href,
        [collections.properties.members]: [MINE, THEIRS],
        [collections.properties.totalMembers]: 2,
      }),
      { status: 200 },
    );
  });
  store.setDrive(OWN_DRIVE);
  store.finishDriveSync(OWN_DRIVE, 1, Date.now());
  store.setServerConnected(true);

  return { store, requests };
}

function messagesIn(store: Store, drive: string) {
  return new CollectionBuilder(store)
    .setProperty(core.properties.parent)
    .setValue(ROOM)
    .setDrive(drive)
    .buildAndFetch();
}

describe('a non-empty local result for a drive this client never synced', () => {
  it('asks the server for the rest', async () => {
    const { store, requests } = setup();
    const collection = await messagesIn(store, HOST_DRIVE);

    expect(requests.length).toBeGreaterThan(0);
    expect(collection.totalMembers).toBe(2);
    expect(await collection.getMemberWithIndex(1)).toBe(THEIRS);
  });

  it('asks once per query, not on every mount', async () => {
    const { store, requests } = setup();
    await messagesIn(store, HOST_DRIVE);
    const asked = requests.length;
    await messagesIn(store, HOST_DRIVE);

    expect(asked).toBeGreaterThan(0);
    expect(requests.length).toBe(asked);
  });

  it('still trusts the local database for a synced drive', async () => {
    const { store, requests } = setup();
    const collection = await messagesIn(store, OWN_DRIVE);

    expect(requests).toEqual([]);
    expect(collection.totalMembers).toBe(1);
  });

  it('asks again after the connection dropped and came back', async () => {
    const { store, requests } = setup();
    await messagesIn(store, HOST_DRIVE);
    const asked = requests.length;

    store.setServerConnected(false);
    store.setServerConnected(true);
    await messagesIn(store, HOST_DRIVE);

    expect(requests.length).toBeGreaterThan(asked);
  });
});
