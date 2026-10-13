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

const makeResponse = async (results: string[]) => {
  const response = new Resource('https://example.com/search');
  await response.set(server.properties.results, results, false);

  return response;
};

const setLocal = (store: Store, search: () => Promise<string[]> | string[]) =>
  store.setClientDb({
    isReady: true,
    isInitialized: true,
    waitForReady: async () => true,
    search,
  } as unknown as Parameters<Store['setClientDb']>[0]);

it('starts the server request without waiting for a slow local search', async () => {
  const store = new Store({ serverUrl: 'https://example.com' });
  store.setServerConnected(true);
  let resolveLocal: (v: string[]) => void = () => undefined;
  const local = new Promise<string[]>(r => (resolveLocal = r));
  setLocal(store, () => local);
  const fetch = vi
    .spyOn(store, 'fetchResourceFromServer')
    .mockResolvedValue(await makeResponse(['did:ad:server', 'did:ad:both']));
  const onPartial = vi.fn();

  const pending = store.search('hello', { onPartial });
  await Promise.resolve();
  await Promise.resolve();

  // Local search is still pending, yet the server was already asked.
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(onPartial).not.toHaveBeenCalled();

  resolveLocal(['did:ad:local', 'did:ad:both']);

  expect(await pending).toEqual([
    'did:ad:local',
    'did:ad:both',
    'did:ad:server',
  ]);
  expect(onPartial).toHaveBeenCalledWith(['did:ad:local', 'did:ad:both']);
});

it('still returns server results when the local search fails', async () => {
  const store = new Store({ serverUrl: 'https://example.com' });
  store.setServerConnected(true);
  setLocal(store, () => Promise.reject(new Error('index busy')));
  vi.spyOn(store, 'fetchResourceFromServer').mockResolvedValue(
    await makeResponse(['did:ad:server']),
  );

  expect(await store.search('hello')).toEqual(['did:ad:server']);
});
