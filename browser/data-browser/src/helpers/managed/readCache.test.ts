import { afterEach, describe, expect, it, vi } from 'vitest';
import { ManagedReadCache } from './readCache';

const url = 'https://account.example/api/me';
const init = { credentials: 'include' } as const;
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('managed metadata reads', () => {
  it('shares concurrent and sequential reads with independently readable bodies, then expires', async () => {
    vi.useFakeTimers();
    const fetch = vi.fn(async () => Response.json({ email: 'a@example.com' }));
    vi.stubGlobal('fetch', fetch);
    const cache = new ManagedReadCache();
    const responses = await Promise.all([
      cache.fetch(url, init),
      cache.fetch(url, init),
    ]);
    for (const response of responses)
      expect(await response.json()).toEqual({ email: 'a@example.com' });
    await cache.fetch(url, init);
    expect(fetch).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(5001);
    await cache.fetch(url, init);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it.each([204, 401, 404, 429, 500])('never caches status %s', async status => {
    const fetch = vi.fn(async () => new Response(null, { status }));
    vi.stubGlobal('fetch', fetch);
    const cache = new ManagedReadCache();
    await cache.fetch(url, init);
    await cache.fetch(url, init);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('isolates provider, token, and request cancellation or cache controls', async () => {
    const fetch = vi.fn(async () => Response.json({}));
    vi.stubGlobal('fetch', fetch);
    const cache = new ManagedReadCache();
    await cache.fetch(url, init);
    await cache.fetch('https://other.example/api/me', init);
    await cache.fetch(url, {
      ...init,
      headers: { Authorization: 'Bearer other' },
    });

    for (let i = 0; i < 2; i++) {
      await cache.fetch(url, { ...init, signal: new AbortController().signal });
      await cache.fetch(url, { ...init, cache: 'no-store' });
    }

    expect(fetch).toHaveBeenCalledTimes(7);
  });

  it('shares explicit refreshes asked for at the same moment, and nothing else', async () => {
    const fetch = vi.fn(async () => Response.json([]));
    vi.stubGlobal('fetch', fetch);
    const cache = new ManagedReadCache();
    const refresh = { ...init, cache: 'no-store' } as const;
    const url2 = 'https://account.example/api/sync-enrollments';
    const [a, b] = await Promise.all([
      cache.fetch(url2, refresh),
      cache.fetch(url2, refresh),
    ]);
    expect(await a.json()).toEqual([]);
    expect(await b.json()).toEqual([]);
    expect(fetch).toHaveBeenCalledTimes(1);
    // Once settled, the next refresh asks again.
    await cache.fetch(url2, refresh);
    expect(fetch).toHaveBeenCalledTimes(2);
    // A refresh is not served from, and does not feed, the shared 5 s read.
    await cache.fetch(url2, init);
    await cache.fetch(url2, init);
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  it('does not reuse pending reads across logout or a completed mutation', async () => {
    let resolve!: (value: Response) => void;
    const fetch = vi
      .fn()
      .mockImplementationOnce(
        () =>
          new Promise<Response>(r => {
            resolve = r;
          }),
      )
      .mockImplementation(async () =>
        Response.json({ email: 'new@example.com' }),
      );
    vi.stubGlobal('fetch', fetch);
    const cache = new ManagedReadCache();
    const old = cache.fetch(url, init);
    await cache.fetch('https://account.example/api/logout', { method: 'POST' });
    resolve(Response.json({ email: 'old@example.com' }));
    await old;
    expect(await (await cache.fetch(url, init)).json()).toEqual({
      email: 'new@example.com',
    });
    cache.invalidate();
    await cache.fetch(url, init);
    expect(fetch).toHaveBeenCalledTimes(4);
  });

  it.each([
    'cloud-vault/drive/confirm-upload',
    'drives/catalog',
    'devices/device',
  ])('retains metadata across unrelated background writes (%s)', async path => {
    const fetch = vi.fn(async () => Response.json({}));
    vi.stubGlobal('fetch', fetch);
    const cache = new ManagedReadCache();
    await cache.fetch(url, init);
    await cache.fetch(`https://account.example/api/${path}`, {
      method: 'POST',
    });
    await cache.fetch(url, init);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('retries network errors and never caches other endpoints', async () => {
    const fetch = vi
      .fn()
      .mockRejectedValueOnce(new Error('offline'))
      .mockImplementation(async () => Response.json({}));
    vi.stubGlobal('fetch', fetch);
    const cache = new ManagedReadCache();
    await expect(cache.fetch(url, init)).rejects.toThrow('offline');
    await cache.fetch(url, init);
    await cache.fetch('https://account.example/api/cloud-vault/drives', init);
    await cache.fetch('https://account.example/api/cloud-vault/drives', init);
    expect(fetch).toHaveBeenCalledTimes(4);
  });
});
