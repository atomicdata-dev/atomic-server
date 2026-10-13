import { expect, it, vi } from 'vitest';
import { Store } from './store.js';
import { core } from './ontologies/core.js';
import type { ClientDbWorker } from './client-db.js';

function storeWithCache(subject: string) {
  const store = new Store({
    serverUrl: 'https://app.example.com',
    connect: false,
  });
  (store as unknown as { _serverConnected: boolean })._serverConnected = true;
  const jsonAd = JSON.stringify({
    '@id': subject,
    [core.properties.isA]: [core.classes.agent],
    [core.properties.name]: 'Polle',
  });
  const read = vi.fn(async () => ({ jsonAd, snapshot: null }));
  store.setClientDb({
    isReady: true,
    isInitialized: true,
    waitForInit: async () => {},
    getResourcesWithSnapshots: async (subjects: string[]) =>
      Promise.all(subjects.map(read)),
    getResourceWithSnapshot: read,
    putResourceWithSnapshot: async () => {},
  } as unknown as ClientDbWorker);

  return { store, read };
}

it('renders a foreign https profile from the local copy while the server is slow', async () => {
  const subject = 'https://old.example.com/agents/polle';
  const { store } = storeWithCache(subject);
  // A server that never answers: the name must come from the cache.
  store.injectFetch(vi.fn(() => new Promise<Response>(() => {})));

  store.getResourceLoading(subject);
  await vi.waitFor(() =>
    expect(store.getResourceLoading(subject).get(core.properties.name)).toBe(
      'Polle',
    ),
  );
  expect(store.getResourceLoading(subject).loading).toBe(false);
});

it('renders an atomic: profile from the local copy without asking the server', async () => {
  const subject = 'atomic:us_FswwqxuSexample';
  const { store } = storeWithCache(subject);
  const fetch = vi.fn(() => new Promise<Response>(() => {}));
  store.injectFetch(fetch);

  store.getResourceLoading(subject);
  await vi.waitFor(() =>
    expect(store.getResourceLoading(subject).get(core.properties.name)).toBe(
      'Polle',
    ),
  );
  expect(store.getResourceLoading(subject).loading).toBe(false);
});
