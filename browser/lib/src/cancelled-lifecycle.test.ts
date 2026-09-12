import { describe, expect, it, vi } from 'vitest';
import { Store } from './store.js';
import { Resource } from './resource.js';
import { ClientDbWorker } from './client-db.js';
import { RequestCancelledError } from './error.js';

describe('cancelled resource lifecycle', () => {
  it('rejects a cancelled cold fetch instead of returning an undefined resource', async () => {
    const store = new Store({ serverUrl: 'https://example.com' });
    const client = (
      store as unknown as {
        client: { fetchResourceHTTP: () => Promise<unknown> };
      }
    ).client;
    vi.spyOn(client, 'fetchResourceHTTP').mockResolvedValue({
      cancelled: true,
    });
    await expect(
      store.getResource('https://example.com/cold'),
    ).rejects.toBeInstanceOf(RequestCancelledError);
  });

  it('stops optional preloading quietly when its fetch is cancelled', async () => {
    const store = new Store({ serverUrl: 'https://example.com' });
    const client = (
      store as unknown as {
        client: { fetchResourceHTTP: () => Promise<unknown> };
      }
    ).client;
    vi.spyOn(client, 'fetchResourceHTTP').mockResolvedValue({
      cancelled: true,
    });
    await expect(
      store.preloadResourceTree('https://example.com/cold', {}),
    ).resolves.toBeUndefined();
  });

  it('classifies pending worker requests as cancelled when the worker is destroyed', async () => {
    const db = new ClientDbWorker('wasm-url', 'worker-url');
    Object.assign(db, {
      role: 'leader',
      worker: { postMessage: vi.fn(), terminate: vi.fn() },
    });
    const assertion = expect(db.flush()).rejects.toBeInstanceOf(
      RequestCancelledError,
    );
    db.destroy();
    await assertion;
    await expect(db.flush()).rejects.toBeInstanceOf(RequestCancelledError);
  });

  it('rejects cancelled persistence without logging a storage failure', async () => {
    const store = new Store();
    const error = new RequestCancelledError('ClientDb worker destroyed');
    store.setClientDb({
      isReady: true,
      putResourceWithSnapshot: async () => {
        throw error;
      },
      flush: async () => undefined,
    } as unknown as Parameters<Store['setClientDb']>[0]);
    const resource = new Resource('did:ad:cancelled-save');
    resource.setStore(store);
    const log = vi.spyOn(console, 'error').mockImplementation(() => undefined);

    try {
      await expect(resource.persistToClientDb()).rejects.toBe(error);
      expect(log).not.toHaveBeenCalled();
    } finally {
      log.mockRestore();
    }
  });
  it('still reports real persistence errors', async () => {
    const store = new Store();
    const error = new Error('disk write failed');
    store.setClientDb({
      isReady: true,
      putResourceWithSnapshot: async () => {
        throw error;
      },
      flush: async () => undefined,
    } as unknown as Parameters<Store['setClientDb']>[0]);
    const resource = new Resource('did:ad:failed-save');
    resource.setStore(store);
    const log = vi.spyOn(console, 'error').mockImplementation(() => undefined);

    try {
      await expect(resource.persistToClientDb()).rejects.toBe(error);
      expect(log).toHaveBeenCalledWith('[persistToClientDb] failed:', error);
    } finally {
      log.mockRestore();
    }
  });
});
