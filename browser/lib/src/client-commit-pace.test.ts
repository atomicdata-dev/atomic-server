import { describe, expect, it, vi } from 'vitest';
import { Client } from './client.js';
import { AtomicError } from './error.js';
import { ErrorCode } from './ws-v2.js';
import type { Commit } from './commit.js';

const commit = {
  subject: 'did:ad:doc',
  signer: 'did:ad:agent:x=',
  createdAt: 1,
  signature: 'sig',
  loroUpdate: 'AAAA',
} as unknown as Commit;

const committed = JSON.stringify({
  '@id': 'did:ad:commit:sig',
  'https://atomicdata.dev/properties/subject': 'did:ad:doc',
  'https://atomicdata.dev/properties/signer': 'did:ad:agent:x=',
  'https://atomicdata.dev/properties/createdAt': 1,
  'https://atomicdata.dev/properties/signature': 'sig',
});

describe('Client.postCommit load signals', () => {
  it('reports the X-Atomic-Pace-Ms header of an accepted commit', async () => {
    const client = new Client(
      vi.fn(
        async () =>
          new Response(committed, {
            status: 200,
            headers: { 'X-Atomic-Pace-Ms': '4200' },
          }),
      ) as unknown as typeof fetch,
    );
    const listener = vi.fn();
    client.paceListener = listener;
    await client.postCommit(commit, 'https://example.com/commit');
    expect(listener).toHaveBeenCalledWith(4200);
  });

  it('stays quiet when the server sends no pace header', async () => {
    const client = new Client(
      vi.fn(
        async () => new Response(committed, { status: 200 }),
      ) as unknown as typeof fetch,
    );
    const listener = vi.fn();
    client.paceListener = listener;
    await client.postCommit(commit, 'https://example.com/commit');
    expect(listener).not.toHaveBeenCalled();
  });

  it.each([
    [503, { 'Retry-After': '3' }, 3000],
    [429, { 'Retry-After': '7' }, 7000],
    [503, { 'Retry-After': '2', 'X-Atomic-Retry-After-Ms': '1740' }, 1740],
    [503, {}, 1000],
  ])(
    'turns HTTP %s %j into a BUSY refusal waiting %sms',
    async (status, headers, ms) => {
      const client = new Client(
        vi.fn(
          async () => new Response('busy', { status, headers }),
        ) as unknown as typeof fetch,
      );
      const error = await client
        .postCommit(commit, 'https://example.com/commit')
        .catch(e => e);
      expect(error).toBeInstanceOf(AtomicError);
      expect(error.code).toBe(ErrorCode.BUSY);
      expect(error.retryAfterMs).toBe(ms);
    },
  );

  it('does not treat other failures as busy', async () => {
    const client = new Client(
      vi.fn(
        async () => new Response('nope', { status: 500 }),
      ) as unknown as typeof fetch,
    );
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const error = await client
      .postCommit(commit, 'https://example.com/commit')
      .catch(e => e);
    expect(error.retryAfterMs).toBeUndefined();
  });
});
