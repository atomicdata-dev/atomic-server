import { expect, it, vi } from 'vitest';
import { Store } from './store.js';
import { Resource } from './resource.js';
import { core } from './ontologies/core.js';
import type { ClientDbWorker } from './client-db.js';

function attach(
  store: Store,
  read: () => Promise<{ jsonAd: string; snapshot: Uint8Array }[]>,
) {
  store.setClientDb({
    isReady: true,
    isInitialized: true,
    waitForInit: async () => {},
    getResourcesWithSnapshots: read,
    putResourceWithSnapshot: async () => {},
  } as unknown as ClientDbWorker);
}

it('merges restored history into the live document without losing a pending edit', async () => {
  const store = new Store({
    serverUrl: 'https://example.test',
    connect: false,
  });
  const subject = 'atomic:restored-open-document';
  const live = store.getResourceLoading(subject, { newResource: true });
  await live.set(core.properties.description, 'Unsent edit', false);
  const remote = new Resource(subject);
  await remote.set(core.properties.name, 'Other device', false);
  attach(store, async () => [
    {
      jsonAd: JSON.stringify({ '@id': subject }),
      snapshot: remote.getLoroDoc()!.export({ mode: 'snapshot' }),
    },
  ]);
  await store.refreshRestoredResources([subject], []);
  expect(store.resources.get(subject)).toBe(live);
  expect(live.get(core.properties.name)).toBe('Other device');
  expect(live.get(core.properties.description)).toBe('Unsent edit');
  expect(live.hasUnsavedChanges()).toBe(true);
});

it('discards a recovery read when its database is replaced', async () => {
  const store = new Store({
    serverUrl: 'https://example.test',
    connect: false,
  });
  let release!: (rows: { jsonAd: string; snapshot: Uint8Array }[]) => void;
  const read = vi.fn(
    () =>
      new Promise<{ jsonAd: string; snapshot: Uint8Array }[]>(resolve => {
        release = resolve;
      }),
  );
  attach(store, read);
  const pending = store.refreshRestoredResources(['atomic:old-account'], []);
  await vi.waitFor(() => expect(read).toHaveBeenCalled());
  attach(store, async () => []);
  release([
    {
      jsonAd: JSON.stringify({
        '@id': 'atomic:old-account',
        [core.properties.name]: 'Private',
      }),
      snapshot: new Uint8Array(),
    },
  ]);
  await expect(pending).rejects.toThrow();
  expect(store.resources.has('atomic:old-account')).toBe(false);
});
