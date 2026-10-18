import { describe, expect, it, vi } from 'vitest';
import { Resource } from './resource.js';
import { Store } from './store.js';
import { core } from './ontologies/core.js';
import type { ClientDbWorker } from './client-db.js';

/**
 * An edit made offline is stored in the local database and nowhere else until
 * the outbox drain reads it back. On a reload that database takes seconds to
 * open, the server's copy of the same resource arrives first, and it was
 * written to the database as soon as it could be: over the edit. The drain then
 * read the server's state back as the edit's, found nothing past the synced
 * baseline and cleared the entry (sync.spec "offline edits sync to server").
 */
describe('writing a server copy to the local database', () => {
  const makeResource = (subject: string, store: Store) => {
    const resource = new Resource(subject);
    resource.setStore(store);
    resource.applyHydratedValues([[core.properties.name, 'Server title']]);
    resource.loading = false;

    return resource;
  };

  const attach = async (store: Store) => {
    const putResourceWithSnapshot = vi.fn(async () => undefined);
    const worker = {
      isReady: true,
      waitForReady: async () => true,
      putResourceWithSnapshot,
    } as unknown as ClientDbWorker;

    store.setClientDb(worker);
    await store.outbox.whenHydrated();

    return putResourceWithSnapshot;
  };

  it('waits while the outbox holds an entry for the subject', async () => {
    const store = new Store({ serverUrl: 'https://example.com' });
    store.expectClientDb();
    const put = await attach(store);

    const subject = store.normalizeSubject('did:ad:resource:edited-offline');
    store.outbox.markDirty(subject);
    store.addResource(makeResource(subject, store));

    expect(put).not.toHaveBeenCalled();

    // Once the drain has delivered the edit the entry is gone and the state is
    // written like any other.
    store.outbox.clearDirty(subject);

    expect(put).toHaveBeenCalledOnce();
    expect(put.mock.calls[0][0]).toBe(subject);
  });

  it('waits until the outbox can say whether it holds an entry', async () => {
    const store = new Store({ serverUrl: 'https://example.com' });
    store.expectClientDb();

    // The outbox reads its rows from the database that is still opening.
    const put = vi.fn(async () => undefined);
    const worker = {
      isReady: true,
      waitForReady: async () => true,
      putResourceWithSnapshot: put,
    } as unknown as ClientDbWorker;
    // Attached, but not yet known to hold (or not hold) the queue.
    (store as unknown as { clientDb: ClientDbWorker }).clientDb = worker;

    const subject = store.normalizeSubject('did:ad:resource:arrives-first');
    store.addResource(makeResource(subject, store));

    expect(store.outbox.hydrated).toBe(false);
    expect(put).not.toHaveBeenCalled();

    store.outbox.databaseUnavailable(undefined);

    expect(put).toHaveBeenCalledOnce();
    expect(put.mock.calls[0][0]).toBe(subject);
  });

  it('writes at once when nothing is pending', async () => {
    const store = new Store({ serverUrl: 'https://example.com' });
    store.expectClientDb();
    const put = await attach(store);

    store.addResource(makeResource('did:ad:resource:plain', store));

    expect(put).toHaveBeenCalledOnce();
  });
});
