import { expect, it, vi } from 'vitest';
import { Store } from './store.js';
import { core } from './ontologies/core.js';
vi.mock('@tomic/react', async () => ({
  core: (await import('./ontologies/core.js')).core,
}));
import { localImportRows } from '../../data-browser/src/chunks/PluginRuns/localImportVerdict';
it.each([true, false])(
  'reads indexed import rows locally (snapshot available: %s)',
  async available => {
    const store = new Store({ serverUrl: 'https://example.com' });
    store.setServerConnected(true);
    const subject = 'did:ad:local-import-row';
    store.setClientDb({
      isReady: true,
      isInitialized: true,
      waitForReady: async () => true,
      waitForInit: async () => undefined,
      query: async () => ({ subjects: [subject], count: 1 }),
      getResourceWithSnapshot: async () => ({
        jsonAd: available
          ? JSON.stringify({
              '@id': subject,
              [core.properties.name]: 'Local row',
            })
          : null,
        snapshot: null,
      }),
      exportAllResources: async () => '[]',
    } as never);
    const remote = vi
      .spyOn(store, 'fetchResourceFromServer')
      .mockRejectedValue(new Error('Server does not have this local row'));
    const result = localImportRows(store, 'did:ad:drive', {
      platform: 'pets',
      properties: {},
      destinations: {
        pet: { table: 'did:ad:table', rowClass: 'did:ad:class' },
      },
    });
    if (available) {
      expect((await result).get(subject)?.[core.properties.name]).toBe(
        'Local row',
      );
    } else {
      await expect(result).rejects.toThrow('not available locally');
    }
    expect(remote).not.toHaveBeenCalled();
  },
);
