import { afterEach, expect, it, vi } from 'vitest';
import { Store } from './store.js';
import { core } from './ontologies/core.js';
import type { ClientDbWorker } from './client-db.js';

afterEach(() => {
  vi.useRealTimers();
});

it('asks the server when the local database does not answer in time', async () => {
  vi.useFakeTimers();
  const store = new Store({
    serverUrl: 'https://app.example.com',
    connect: false,
  });
  (store as unknown as { _serverConnected: boolean })._serverConnected = true;
  // A local database whose read never comes back, as with a leader tab that
  // stopped answering.
  store.setClientDb({
    isReady: true,
    isInitialized: true,
    waitForInit: async () => {},
    getResourcesWithSnapshots: () => new Promise(() => {}),
    getResourceWithSnapshot: () => new Promise(() => {}),
    putResourceWithSnapshot: async () => {},
  } as unknown as ClientDbWorker);
  const subject = 'https://app.example.com/drive/home';
  const fetch = vi.fn(
    async () =>
      new Response(
        JSON.stringify({ '@id': subject, [core.properties.name]: 'Home' }),
      ),
  );
  store.injectFetch(fetch);

  const loading = store.getResource(subject);
  await vi.advanceTimersByTimeAsync(500);
  expect(fetch).not.toHaveBeenCalled();
  await vi.advanceTimersByTimeAsync(700);
  const resource = await loading;

  expect(fetch).toHaveBeenCalled();
  expect(resource.get(core.properties.name)).toBe('Home');
});

it('asks the server almost at once while a drive sync is running', async () => {
  vi.useFakeTimers();
  const store = new Store({
    serverUrl: 'https://app.example.com',
    connect: false,
  });
  (store as unknown as { _serverConnected: boolean })._serverConnected = true;
  // A drive sync keeps the worker busy writing what the server sends, so a
  // read queues behind those writes.
  store.startDriveSync();
  store.setClientDb({
    isReady: true,
    isInitialized: true,
    waitForInit: async () => {},
    getResourcesWithSnapshots: () => new Promise(() => {}),
    getResourceWithSnapshot: () => new Promise(() => {}),
    putResourceWithSnapshot: async () => {},
  } as unknown as ClientDbWorker);
  const subject = 'https://app.example.com/drive/home';
  const fetch = vi.fn(
    async () =>
      new Response(
        JSON.stringify({ '@id': subject, [core.properties.name]: 'Home' }),
      ),
  );
  store.injectFetch(fetch);

  const loading = store.getResource(subject);
  await vi.advanceTimersByTimeAsync(200);
  const resource = await loading;

  expect(fetch).toHaveBeenCalled();
  expect(resource.get(core.properties.name)).toBe('Home');
});
