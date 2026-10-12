// Regression test for existing behaviour, not for a new change: an errored
// Resource stays cached in store.resources, so a 404 is fetched only once.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Store } from './store.js';

const SPEAKER = 'https://atomicdata.dev/properties/demo/speaker';

function storeWithStatus(status: number) {
  const fetchMock = vi.fn(
    async () => new Response('not here', { status }),
  ) as unknown as typeof fetch;
  vi.stubGlobal('fetch', fetchMock);

  return { store: new Store({ serverUrl: 'https://example.com' }), fetchMock };
}

function speakerRequests(fetchMock: ReturnType<typeof vi.fn>) {
  return fetchMock.mock.calls.filter(([url]) =>
    String(url).includes('demo/speaker'),
  );
}

describe('a property that is not found', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('is requested once, however often it is looked up', async () => {
    const { store, fetchMock } = storeWithStatus(404);

    for (let i = 0; i < 3; i++) {
      await expect(store.getProperty(SPEAKER)).rejects.toThrow();
    }

    expect(speakerRequests(fetchMock)).toHaveLength(1);
  });

  it('is requested once for every other subject too', async () => {
    const { store, fetchMock } = storeWithStatus(404);
    const other = 'https://atomicdata.dev/properties/demo/other';

    for (let i = 0; i < 3; i++) {
      await store.getResource(other);
    }

    expect(
      fetchMock.mock.calls.filter(([url]) =>
        String(url).includes('demo/other'),
      ),
    ).toHaveLength(1);
  });
});
