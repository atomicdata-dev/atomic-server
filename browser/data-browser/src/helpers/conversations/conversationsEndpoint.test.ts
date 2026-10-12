import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  hasConversationsEndpoint,
  resetConversationsEndpointCache,
} from './conversationsEndpoint';

const answer = (status: number, type: string) =>
  new Response('', { status, headers: { 'content-type': type } });

describe('hasConversationsEndpoint', () => {
  beforeEach(() => {
    resetConversationsEndpointCache();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('is false for a server that answers with its HTML page', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => answer(200, 'text/html; charset=utf-8')),
    );

    expect(await hasConversationsEndpoint('http://app', '/conversations')).toBe(
      false,
    );
  });

  it('is false for a server that answers 404', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => answer(404, 'application/json')),
    );

    expect(await hasConversationsEndpoint('http://old', '/conversations')).toBe(
      false,
    );
  });

  it('is true when the endpoint answers, even if it asks for a signature', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => answer(401, 'application/ad+json')),
    );

    expect(
      await hasConversationsEndpoint('http://node', '/conversations'),
    ).toBe(true);
  });

  it('asks once per server, and does not remember a network error', async () => {
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValue(answer(200, 'text/html'));
    vi.stubGlobal('fetch', fetchMock);

    // The failed ask is not remembered, so the next one asks again and learns.
    expect(await hasConversationsEndpoint('http://x', '/conversations')).toBe(
      true,
    );
    expect(await hasConversationsEndpoint('http://x', '/conversations')).toBe(
      false,
    );
    expect(await hasConversationsEndpoint('http://x', '/conversations')).toBe(
      false,
    );
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('gives up on a server that never answers', async () => {
    // The timeout fires at once, so the test does not wait five seconds.
    vi.spyOn(AbortSignal, 'timeout').mockReturnValue(AbortSignal.abort());
    vi.stubGlobal(
      'fetch',
      vi.fn(
        (_url: string, init?: RequestInit) =>
          new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener('abort', () =>
              reject(init.signal?.reason),
            );
            if (init?.signal?.aborted) reject(init.signal.reason);
          }),
      ),
    );

    expect(
      await hasConversationsEndpoint('http://hang', '/conversations'),
    ).toBe(true);
  });
});
