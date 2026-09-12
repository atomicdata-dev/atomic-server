import { expect, it, vi } from 'vitest';
import { Store, Resource, server } from './index.js';

it('server-only lookup does not wait for a busy local index or a WebSocket', async () => {
  const store = new Store({ serverUrl: 'https://example.com' });
  const localSearch = vi.fn(() => {
    throw new Error('Local index is busy importing');
  });
  store.setClientDb({
    isReady: true,
    isInitialized: true,
    waitForReady: async () => true,
    search: localSearch,
  } as unknown as Parameters<Store['setClientDb']>[0]);
  const response = new Resource('https://example.com/search');
  await response.set(
    server.properties.results,
    ['did:ad:imported-root'],
    false,
  );
  const fetch = vi
    .spyOn(store, 'fetchResourceFromServer')
    .mockResolvedValue(response);

  const result = await store.search('', {
    serverOnly: true,
    parents: 'did:ad:destination',
    limit: 1,
  });

  expect(result).toEqual(['did:ad:imported-root']);
  expect(localSearch).not.toHaveBeenCalled();
  expect(fetch).toHaveBeenCalledWith(expect.stringContaining('/search?'), {
    noWebSocket: true,
  });
});
