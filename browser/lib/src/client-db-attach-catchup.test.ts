import { describe, expect, it, vi } from 'vitest';
import { Resource } from './resource.js';
import { Store } from './store.js';
import { core } from './ontologies/core.js';
import type { ClientDbWorker } from './client-db.js';

/**
 * Signing in swaps the anonymous local database for the agent's own one, and
 * `initClientDb` detaches the store's worker synchronously the moment the
 * identity changes — the replacement attaches seconds later, once its file is
 * open. Everything the server delivers in that window arrives at `addResource`
 * with no database to write to.
 *
 * Nothing re-adds a resource that was applied once, so those writes used to be
 * lost for the whole session: a drive sync landing in the window left its
 * resources in memory and out of the local index, `finishDriveSync` vouched for
 * the drive regardless, and `Collection.finishLocalDbPage` then treated the
 * empty index as authoritative and never asked the server. A second device
 * would open a drive and show none of its contents.
 */
describe('state that arrives while no local database is attached', () => {
  const makeResource = (subject: string, store: Store) => {
    const resource = new Resource(subject);
    resource.setStore(store);
    resource.applyHydratedValues([[core.properties.name, 'Child']]);
    resource.loading = false;

    return resource;
  };

  const fakeWorker = () => {
    const putResourceWithSnapshot = vi.fn(async () => undefined);

    return {
      putResourceWithSnapshot,
      worker: {
        isReady: true,
        waitForReady: async () => true,
        putResourceWithSnapshot,
      } as unknown as ClientDbWorker,
    };
  };

  it('is written once a database attaches', async () => {
    const store = new Store({ serverUrl: 'https://example.com' });
    store.expectClientDb();

    const child = makeResource('did:ad:resource:child', store);
    store.addResource(child);

    const { worker, putResourceWithSnapshot } = fakeWorker();
    expect(putResourceWithSnapshot).not.toHaveBeenCalled();

    store.setClientDb(worker);
    // A write waits for the outbox to say whether an offline edit is stored in
    // the database it is about to go to.
    await store.outbox.whenHydrated();

    expect(putResourceWithSnapshot).toHaveBeenCalledOnce();
    // The store normalises on the way in, so ask the resource for its subject
    // rather than repeating the one it was constructed with.
    expect(putResourceWithSnapshot.mock.calls[0][0]).toBe(child.subject);
  });

  it('does not queue anything when the app has no database at all', () => {
    // An app that opted out never attaches one, so remembering writes for it
    // would grow a set nothing ever drains.
    const store = new Store({ serverUrl: 'https://example.com' });
    store.addResource(makeResource('did:ad:resource:no-db', store));

    const { worker, putResourceWithSnapshot } = fakeWorker();
    store.setClientDb(worker);

    expect(putResourceWithSnapshot).not.toHaveBeenCalled();
  });

  it('goes to the database the sign-in attached, not the one it replaced', async () => {
    // The sequence a second device actually runs: the anonymous database is
    // open, signing in detaches it, the drive sync lands in the gap, and the
    // agent's own database attaches after it.
    const store = new Store({ serverUrl: 'https://example.com' });
    store.expectClientDb();

    const anon = fakeWorker();
    store.setClientDb(anon.worker);
    store.setClientDb(undefined);

    const child = makeResource('did:ad:resource:swapped', store);
    store.addResource(child);

    const owned = fakeWorker();
    store.setClientDb(owned.worker);
    await store.outbox.whenHydrated();

    expect(owned.putResourceWithSnapshot).toHaveBeenCalledOnce();
    expect(owned.putResourceWithSnapshot.mock.calls[0][0]).toBe(child.subject);
    expect(anon.putResourceWithSnapshot).not.toHaveBeenCalled();
  });
});
