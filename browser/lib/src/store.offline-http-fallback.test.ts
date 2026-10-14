import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  NOT_AVAILABLE_LOCALLY_MESSAGE,
  NOT_AVAILABLE_SERVER_UNREACHABLE_MESSAGE,
  isNotAvailableLocally,
  isServerUnreachable,
} from './error.js';
import { Store } from './store.js';

const SUBJECT = 'did:ad:offlinefallbacksubject';

/** A store whose socket never comes up and whose local database is empty. */
function offlineStore() {
  const store = new Store({ serverUrl: 'https://example.com' });
  vi.spyOn(store, 'waitForServerConnected').mockResolvedValue(false);

  return store;
}

describe('a resource with no local copy and no websocket', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('is fetched once over HTTP and the answer is kept', async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            '@id': SUBJECT,
            'https://atomicdata.dev/properties/name': 'Chat',
          }),
          { status: 200, headers: { 'Content-Type': 'application/ad+json' } },
        ),
    ) as unknown as typeof fetch;
    vi.stubGlobal('fetch', fetchMock);
    const store = offlineStore();

    const resource = await store.getResource(SUBJECT);

    expect(resource.error).toBeUndefined();
    expect(resource.loading).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('says the server is unreachable only when the HTTP request failed', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch');
      }) as unknown as typeof fetch,
    );
    const store = offlineStore();

    const resource = await store.getResource(SUBJECT);

    expect(resource.loading).toBe(false);
    expect(isNotAvailableLocally(resource.error)).toBe(true);
    expect(isServerUnreachable(resource.error)).toBe(true);
    expect(resource.error?.message).toBe(
      NOT_AVAILABLE_SERVER_UNREACHABLE_MESSAGE,
    );
  });

  it('keeps a real server answer such as 404 instead of "not on this device"', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () => new Response('nope', { status: 404 }),
      ) as unknown as typeof fetch,
    );
    const store = offlineStore();

    const resource = await store.getResource(SUBJECT);

    expect(resource.error).toBeDefined();
    expect(isNotAvailableLocally(resource.error)).toBe(false);
    expect(resource.error?.message).not.toBe(NOT_AVAILABLE_LOCALLY_MESSAGE);
  });

  it('does not ask an origin that is known to run no node', async () => {
    const fetchMock = vi.fn(
      async () => new Response('<!doctype html>', { status: 200 }),
    ) as unknown as typeof fetch;
    vi.stubGlobal('fetch', fetchMock);
    const store = offlineStore();
    store.setServerUrl('https://example.com', { connect: false });

    const resource = await store.getResource(SUBJECT);

    expect(fetchMock).not.toHaveBeenCalled();
    expect(resource.error?.message).toBe(NOT_AVAILABLE_LOCALLY_MESSAGE);
  });
});
