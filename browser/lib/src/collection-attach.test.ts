import { describe, expect, it, vi } from 'vitest';
import { Collection } from './collection.js';
import { Store } from './store.js';
import { core } from './ontologies/core.js';
import type { ClientDbWorker } from './client-db.js';

describe('collection queries during database attachment', () => {
  it('waits for the expected local database before choosing the server', async () => {
    const store = new Store({ serverUrl: 'https://example.com' });
    const drive = 'did:ad:test-drive';
    store.setDrive(drive);
    store.finishDriveSync(drive, 1, Date.now());
    store.setServerConnected(true);
    store.expectClientDb();
    const remote = vi
      .spyOn(store, 'fetchResourceFromServer')
      .mockRejectedValue(new Error('unexpected remote query'));
    const query = vi.fn(async () => ({
      subjects: [],
      resources: [],
      count: 0,
    }));
    const collection = new Collection(store, 'https://example.com', {
      page_size: '30',
      include_nested: false,
      property: core.properties.parent,
      value: drive,
      drive,
    });
    await Promise.resolve();
    store.setClientDb({
      isReady: true,
      waitForReady: async () => true,
      query,
    } as unknown as ClientDbWorker);
    await collection.waitForReady();
    expect(remote).not.toHaveBeenCalled();
    expect(query).toHaveBeenCalledOnce();
  });
});
