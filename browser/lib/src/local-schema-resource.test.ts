import { expect, it, vi } from 'vitest';
import { Store } from './store.js';
import { core } from './ontologies/core.js';
import { server } from './ontologies/server.js';

vi.mock('@tomic/react', async () => ({
  core: (await import('./ontologies/core.js')).core,
  readConnectionSubjects: vi.fn(),
}));
import {
  localSchemaStore,
  ensureLocalInstallationResource,
} from '../../data-browser/src/chunks/PluginRuns/installationResources';

it('recovers a locally indexed schema after reload while the server lacks it', async () => {
  const store = new Store({ serverUrl: 'https://example.com' });
  store.setServerConnected(true);
  const drive = 'did:ad:calendar-drive';
  const ontology = 'did:ad:calendar-ontology';
  const subject = 'did:ad:local-property';
  const jsonAd = JSON.stringify({
    '@id': subject,
    [core.properties.isA]: [core.classes.property],
    [core.properties.parent]: ontology,
    [server.properties.drive]: drive,
    [core.properties.localId]: 'schema:property:plugin-source',
    [core.properties.shortname]: 'plugin-source',
  });
  store.setClientDb({
    isReady: true,
    isInitialized: true,
    waitForReady: async () => true,
    waitForInit: async () => undefined,
    getResourceWithSnapshot: async (id: string) => ({
      jsonAd: id === subject ? jsonAd : null,
      snapshot: null,
    }),
    query: async () => ({ subjects: [subject], count: 1 }),
    exportAllResources: async () => '[]',
  } as never);
  const remote = vi
    .spyOn(store, 'fetchResourceFromServer')
    .mockRejectedValue(
      new Error(
        `Resource not found. DID Resource ${subject} not found locally`,
      ),
    );

  const recovered = await localSchemaStore(store).findByLocalId(
    drive,
    ontology,
    'schema:property:plugin-source',
  );

  expect(recovered?.subject).toBe(subject);
  expect(recovered?.get(core.properties.shortname)).toBe('plugin-source');
  expect(remote).not.toHaveBeenCalled();
});

it('refuses to recreate a locally indexed installation whose snapshot is missing', async () => {
  const store = new Store({ serverUrl: 'https://example.com' });
  store.setServerConnected(true);
  store.setClientDb({
    isReady: true,
    isInitialized: true,
    waitForInit: async () => undefined,
    query: async () => ({ subjects: ['did:ad:missing'], count: 1 }),
    getResourceWithSnapshot: async () => ({ jsonAd: null, snapshot: null }),
    exportAllResources: async () => '[]',
  } as never);
  const create = vi.spyOn(store, 'newResource');
  const remote = vi.spyOn(store, 'fetchResourceFromServer');
  await expect(
    ensureLocalInstallationResource(store, 'did:ad:drive', {
      parent: 'did:ad:drive',
      localId: 'installation',
      isA: [],
      propVals: {},
    }),
  ).rejects.toThrow('not available locally');
  expect(create).not.toHaveBeenCalled();
  expect(remote).not.toHaveBeenCalled();
});

it('distinguishes an unavailable local database from a missing resource', async () => {
  const store = new Store({ serverUrl: 'https://example.com' });
  await expect(store.getLocalResource('did:ad:missing')).rejects.toThrow(
    'Local resource database is unavailable',
  );
});
