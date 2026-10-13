import { afterEach, expect, it, vi } from 'vitest';
import { Store } from './store.js';
import { Resource } from './resource.js';
import { Agent } from './agent.js';
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

it.each([50, 6000])(
  'rechecks the expected database attached after %i ms when the server returns a 404 resource',
  async attachDelay => {
    vi.useFakeTimers();
    const store = new Store({
      serverUrl: 'https://app.example.com',
      connect: false,
    });
    (store as unknown as { _serverConnected: boolean })._serverConnected = true;
    store.expectClientDb();
    const subject = 'atomic:cold-local-file';
    const fetch = vi.fn(
      async () => new Response('Resource not found', { status: 404 }),
    );
    store.injectFetch(fetch);
    const loading = store.getResource(subject);
    await vi.advanceTimersByTimeAsync(attachDelay);
    expect(fetch).toHaveBeenCalled();

    const row = {
      jsonAd: JSON.stringify({
        '@id': subject,
        [core.properties.name]: 'Local file',
      }),
      snapshot: null,
    };
    store.setClientDb({
      isReady: true,
      isInitialized: true,
      waitForInit: async () => true,
      getResourcesWithSnapshots: async () => [row],
      getResourceWithSnapshot: async () => row,
      putResourceWithSnapshot: async () => {},
    } as unknown as ClientDbWorker);
    await vi.advanceTimersByTimeAsync(50);
    const resource = await loading;
    expect(resource.error).toBeUndefined();
    expect(resource.get(core.properties.name)).toBe('Local file');
  },
);

it.each([100, 6000])(
  'does not retry an old identity read when identity changes after %i ms',
  async changeAfter => {
    vi.useFakeTimers();
    const store = new Store({
      serverUrl: 'https://app.example.com',
      connect: false,
    });
    store.setServerConnected(true);
    store.expectClientDb();
    store.injectFetch(
      async () => new Response('Resource not found', { status: 404 }),
    );
    const subject = 'atomic:old-identity-read';
    const loading = store.getResource(subject);
    await vi.advanceTimersByTimeAsync(changeAfter);
    const keys = await Agent.generateKeyPair();
    store.setAgent(
      Agent.fromSecret(
        Agent.buildSecret(keys.privateKey, `atomic:agent:${keys.publicKey}`),
        'js',
      ),
    );
    await vi.advanceTimersByTimeAsync(6000);
    const read = vi.fn(async (subjects: string[]) =>
      subjects.map(() => ({ jsonAd: null, snapshot: null })),
    );
    store.setClientDb({
      isReady: true,
      isInitialized: true,
      waitForInit: async () => true,
      getResourcesWithSnapshots: read,
      putResourceWithSnapshot: async () => {},
    } as unknown as ClientDbWorker);
    await vi.advanceTimersByTimeAsync(50);
    await loading;
    expect(read.mock.calls.flatMap(([subjects]) => subjects)).not.toContain(
      subject,
    );
  },
);

it('merges a restored profile snapshot while retaining an unsynced local edit', async () => {
  const store = new Store({
    serverUrl: 'https://app.example.com',
    connect: false,
  });
  const subject = 'atomic:agent:restored-profile';
  store.registerLocalOnlyDrive(subject);
  const profile = store.getResourceLoading(subject, { newResource: true });
  await profile.set(core.properties.description, 'Pending local edit', false);
  const restored = new Resource(subject);
  await restored.set(core.properties.name, 'Restored person', false);
  const row = {
    jsonAd: JSON.stringify({
      '@id': subject,
      [core.properties.name]: 'Restored person',
    }),
    snapshot: restored.getLoroDoc()!.export({ mode: 'snapshot' }),
  };
  store.setClientDb({
    isReady: true,
    isInitialized: true,
    waitForInit: async () => {},
    getResourcesWithSnapshots: async (subjects: string[]) =>
      subjects.map(() => row),
    getResourceWithSnapshot: async () => row,
    putResourceWithSnapshot: async () => {},
  } as unknown as ClientDbWorker);

  await store.reloadResource(subject);

  expect(profile.get(core.properties.name)).toBe('Restored person');
  expect(profile.get(core.properties.description)).toBe('Pending local edit');
  expect(profile.hasUnsavedChanges()).toBe(true);
  expect(profile.loading).toBe(false);
});
