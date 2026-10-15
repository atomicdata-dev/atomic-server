import { describe, it, expect, vi, afterEach } from 'vitest';
import { hostingRequest, sameWebsiteOutput } from './hostingClient';
import { signRequest, type Store } from '@tomic/lib';
vi.mock('@tomic/lib', () => ({
  signRequest: vi.fn(async () => ({ 'x-atomic-signature': 'proof' })),
  errorMessageFromResponse: (body: string) => body,
}));
afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});
const store = {
  getServerUrl: () => 'https://atomic.example',
  getDrive: () => 'did:ad:drive',
  getAgent: () => ({ subject: 'owner', privateKey: 'secret' }),
} as unknown as Store;
describe('hosting control requests', () => {
  it('signs the API and excludes the key from uploads', async () => {
    const fetch = vi.fn(async (..._args: unknown[]) => ({
      ok: true,
      json: async () => ({ state: null }),
    }));
    vi.stubGlobal('fetch', fetch);
    await hostingRequest(store, 'did:ad:website', '/deployments', {
      version: 1,
      files: { 'index.html': 'Bread' },
    });
    const [url, options] = fetch.mock.calls[0] as [URL, RequestInit];
    expect(url.origin).toBe('https://atomic.example');
    expect(url.searchParams.get('drive')).toBe('did:ad:drive');
    // Version 2: the signature covers the method and the exact body sent.
    expect(signRequest).toHaveBeenCalledWith(
      url.toString(),
      store.getAgent(),
      {},
      { method: 'POST', body: options.body },
    );
    expect(options.credentials).toBe('omit');
    expect(options.redirect).toBe('error');
    expect(options.body).not.toContain('secret');
  });
  it('surfaces conflicts without retrying', async () => {
    const fetch = vi.fn(async () => ({
      ok: false,
      status: 409,
      text: async () => 'Publication changed',
    }));
    vi.stubGlobal('fetch', fetch);
    await expect(
      hostingRequest(store, 'project', '/activate', {
        expectedRevision: 1,
        deployment: 'old',
      }),
    ).rejects.toThrow('Publication changed');
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});

describe('published output comparison', () => {
  it('ignores entry order and treats missing assets as empty', () => {
    expect(
      sameWebsiteOutput(
        { version: 1, files: { a: 'one', b: 'two' } },
        { version: 1, files: { b: 'two', a: 'one' }, assets: {} },
      ),
    ).toBe(true);
  });
  it('detects changed text, removed files and changed image hashes', () => {
    const base = {
      version: 1 as const,
      files: { 'index.html': 'Bread' },
      assets: { 'assets/photo.webp': 'old' },
    };
    expect(
      sameWebsiteOutput(base, { ...base, files: { 'index.html': 'Cake' } }),
    ).toBe(false);
    expect(sameWebsiteOutput(base, { ...base, files: {} })).toBe(false);
    expect(
      sameWebsiteOutput(base, {
        ...base,
        assets: { 'assets/photo.webp': 'new' },
      }),
    ).toBe(false);
  });
});
