import { expect, it, vi } from 'vitest';
import { Store, isEmbeddedVocabulary } from './store.js';
import { taskSchema } from './task-schema.js';
import { server } from './ontologies/server.js';
import { forms } from './ontologies/forms.js';

const TODO = taskSchema.tags.Todo;

it('counts the task vocabulary as embedded and a drive resource as not', () => {
  expect(isEmbeddedVocabulary(TODO)).toBe(true);
  expect(isEmbeddedVocabulary(taskSchema.properties.status)).toBe(true);
  expect(isEmbeddedVocabulary('https://atomicdata.dev/task/v1')).toBe(true);
  expect(isEmbeddedVocabulary(server.classes.installation)).toBe(true);
  expect(isEmbeddedVocabulary(server.classes.release)).toBe(true);
  expect(isEmbeddedVocabulary(forms.classes.form)).toBe(true);
  expect(isEmbeddedVocabulary(forms.properties.formFields)).toBe(true);
  expect(isEmbeddedVocabulary('did:ad:whatever')).toBe(false);
  expect(isEmbeddedVocabulary('https://atomicdata.dev/properties/name')).toBe(
    false,
  );
});

/**
 * The regression this guards: a kanban board rendered its column headings as
 * `...` past 45 seconds because nothing would ask the server for four tiny tag
 * resources until a busy client-database worker had answered first.
 */
it('asks the server for embedded vocabulary without waiting for the local database', async () => {
  const store = new Store({ serverUrl: 'https://example.com' });
  store.setServerConnected(true);

  // A local database that never answers — the shape of a worker starved by a
  // loaded machine.
  let localAsked = false;
  (store as unknown as { clientDb: unknown }).clientDb = {
    isInitialized: true,
    isReady: true,
    waitForInit: async () => true,
    getResourcesWithSnapshots: async () => {
      localAsked = true;

      return new Promise(() => {
        /* never settles */
      });
    },
  };

  const fromServer = vi
    .spyOn(store, 'fetchResourceFromServer')
    .mockImplementation(async subject => {
      const resource = store.getResourceLoading(subject, {
        allowIncomplete: true,
      });
      resource.loading = false;

      return resource;
    });

  await (
    store as unknown as {
      fetchResourceWithLocalFallback(s: string): Promise<void>;
    }
  ).fetchResourceWithLocalFallback(TODO);

  expect(fromServer).toHaveBeenCalledWith(TODO, expect.anything());
  expect(localAsked).toBe(false);
});

it('still falls back to the local path when the server refuses', async () => {
  const store = new Store({ serverUrl: 'https://example.com' });
  store.setServerConnected(true);

  let localAsked = false;
  (store as unknown as { clientDb: unknown }).clientDb = {
    isInitialized: true,
    isReady: true,
    waitForInit: async () => true,
    getResourcesWithSnapshots: async (subjects: string[]) => {
      localAsked = true;

      return subjects.map(() => ({ jsonAd: null, snapshot: null }));
    },
  };

  vi.spyOn(store, 'fetchResourceFromServer').mockRejectedValue(
    new Error('offline'),
  );

  await (
    store as unknown as {
      fetchResourceWithLocalFallback(s: string): Promise<void>;
    }
  ).fetchResourceWithLocalFallback(TODO);

  expect(localAsked).toBe(true);
});
