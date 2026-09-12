import { describe, it, vi } from 'vitest';
import {
  buildSearchSubject,
  removeCachedSearchResults,
  SearchOpts,
} from './search.js';
import { Store } from './store.js';
import { Resource } from './resource.js';

describe('search.ts', () => {
  it('Builds a good search URL', ({ expect }) => {
    const serverURL = 'https://test.com';
    const query = 'test';
    const searchOpts: SearchOpts = {
      include: true,
      limit: 30,
      parents: 'https://test.com/parent',
      filters: {
        age: '10',
      },
    };
    const built = buildSearchSubject(serverURL, query, searchOpts);
    expect(built).toBe(
      'https://test.com/search?q=test&include=true&limit=30&filters=age%3A%2210%22&parents=https%3A%2F%2Ftest.com%2Fparent',
    );
  });

  it('Puts property URLs in filters without escaping', ({ expect }) => {
    const built = buildSearchSubject('https://test.com', '', {
      filters: {
        'https://atomicdata.dev/properties/isA':
          'https://atomicdata.dev/classes/File',
      },
    });
    expect(built).toContain(
      'filters=https%3A%2F%2Fatomicdata.dev%2Fproperties%2FisA%3A%22https%3A%2F%2Fatomicdata.dev%2Fclasses%2FFile%22',
    );
  });
});

it('invalidating search projections does not delete persisted resources or leave sync pending', ({
  expect,
}) => {
  const store = new Store({ serverUrl: 'https://example.com' });
  const subject = buildSearchSubject(store.getServerUrl(), 'website');
  store.addResource(new Resource(subject));
  const removeResource = vi.fn(() => new Promise<void>(() => {}));
  store.setClientDb({ removeResource } as unknown as Parameters<
    Store['setClientDb']
  >[0]);

  removeCachedSearchResults(store);

  expect(store.resources.has(subject)).toBe(false);
  expect(removeResource).not.toHaveBeenCalled();
  expect(store.getSyncStatus().pendingDirtyCount).toBe(0);
});
