import { afterEach, describe, expect, it, vi } from 'vitest';
import { Store } from './store.js';
import { AtomicError, ErrorType } from './error.js';
import type { Commit } from './commit.js';
import { ErrorCode } from './ws-v2.js';

afterEach(() => vi.unstubAllGlobals());

describe('commit transport fallback', () => {
  it.each([undefined, ErrorCode.SYNC_REJECTED])(
    'does not retry an enrollment refusal over HTTP (code %s)',
    async code => {
      const store = new Store({ serverUrl: 'https://example.com' });
      vi.stubGlobal('WebSocket', { OPEN: 1 });
      const rejected = new AtomicError(
        'Drive did:ad:private is not enrolled for sync on this node.',
        ErrorType.Server,
        code,
      );
      const internals = store as unknown as {
        getWebSocketForEndpoint: () => unknown;
        client: { postCommit: () => Promise<Commit> };
      };
      vi.spyOn(internals, 'getWebSocketForEndpoint').mockReturnValue({
        readyState: 1,
        postCommit: vi.fn().mockRejectedValue(rejected),
      });
      const http = vi
        .spyOn(internals.client, 'postCommit')
        .mockRejectedValue(rejected);
      await expect(
        store.postCommit(
          { subject: 'did:ad:edit' } as Commit,
          'https://example.com/commit',
        ),
      ).rejects.toBe(rejected);
      expect(http).not.toHaveBeenCalled();
    },
  );

  it('still uses HTTP when the socket transport fails', async () => {
    const store = new Store({ serverUrl: 'https://example.com' });
    vi.stubGlobal('WebSocket', { OPEN: 1 });
    const commit = { subject: 'did:ad:edit' } as Commit;
    const internals = store as unknown as {
      getWebSocketForEndpoint: () => unknown;
      client: { postCommit: () => Promise<Commit> };
    };
    vi.spyOn(internals, 'getWebSocketForEndpoint').mockReturnValue({
      readyState: 1,
      postCommit: vi.fn().mockRejectedValue(new Error('socket closed')),
    });
    const http = vi
      .spyOn(internals.client, 'postCommit')
      .mockResolvedValue(commit);
    await expect(
      store.postCommit(commit, 'https://example.com/commit'),
    ).resolves.toBe(commit);
    expect(http).toHaveBeenCalledTimes(1);
  });
});
