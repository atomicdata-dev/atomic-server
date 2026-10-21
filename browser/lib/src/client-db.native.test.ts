import { describe, expect, it } from 'vitest';
import { encodeB64 } from './base64.js';
import {
  NativeClientDb,
  NativeCryptoProvider,
  type NativeChannel,
} from './client-db.native.js';

/** A host that records what it is asked and answers from a table. */
function host(answers: Record<string, (args: unknown[]) => unknown>) {
  const calls: Array<[string, unknown[]]> = [];
  const channel: NativeChannel = {
    async call(method, args) {
      calls.push([method, args]);
      const answer = answers[method];

      if (!answer) throw new Error(`no answer for ${method}`);

      return answer(args);
    },
  };

  return { channel, calls };
}

describe('NativeClientDb', () => {
  it('reads many resources in one round trip and decodes the snapshots', async () => {
    const snapshot = new Uint8Array([1, 2, 3, 250]);
    const { channel, calls } = host({
      getResourcesWithSnapshots: () => [
        { jsonAd: '{"@id":"a"}', snapshot: encodeB64(snapshot) },
        { jsonAd: null, snapshot: null },
      ],
    });
    const db = new NativeClientDb(channel);

    const rows = await db.getResourcesWithSnapshots(['a', 'b']);

    expect(calls).toEqual([['getResourcesWithSnapshots', [['a', 'b']]]]);
    expect(rows[0].jsonAd).toBe('{"@id":"a"}');
    expect(Array.from(rows[0].snapshot!)).toEqual([1, 2, 3, 250]);
    expect(rows[1]).toEqual({ jsonAd: null, snapshot: null });
  });

  it('a single read goes through the batch call', async () => {
    const { channel, calls } = host({
      getResourcesWithSnapshots: () => [{ jsonAd: 'x', snapshot: null }],
    });
    const one = await new NativeClientDb(channel).getResourceWithSnapshot('s');

    expect(one.jsonAd).toBe('x');
    expect(calls[0][0]).toBe('getResourcesWithSnapshots');
  });

  it('is ready once the host says so, and asks only once', async () => {
    const { channel, calls } = host({ init: () => true });
    const db = new NativeClientDb(channel);

    expect(db.isReady).toBe(false);
    expect(await db.waitForInit()).toBe(true);
    expect(await db.waitForReady()).toBe(true);
    expect(db.isReady).toBe(true);
    expect(calls.filter(([m]) => m === 'init')).toHaveLength(1);
  });

  it('a host that cannot open its store is not ready, and says why', async () => {
    const { channel } = host({
      init: () => {
        throw new Error('store is locked');
      },
    });
    const db = new NativeClientDb(channel);

    expect(await db.waitForInit()).toBe(false);
    expect(db.initError?.message).toBe('store is locked');
  });

  it('sends bytes to the host as base64', async () => {
    const { channel, calls } = host({
      putResourceWithSnapshot: () => undefined,
      putBlob: () => undefined,
      getBlob: () => encodeB64(new Uint8Array([9, 8])),
    });
    const db = new NativeClientDb(channel);

    await db.putResourceWithSnapshot('s', '{}', new Uint8Array([4, 5]));
    await db.putBlob(new Uint8Array([1]), new Uint8Array([2, 3]));
    const blob = await db.getBlob(new Uint8Array([1]));

    expect(calls[0][1]).toEqual([
      's',
      '{}',
      encodeB64(new Uint8Array([4, 5])),
      null,
    ]);
    expect(calls[1][1]).toEqual([
      encodeB64(new Uint8Array([1])),
      encodeB64(new Uint8Array([2, 3])),
    ]);
    expect(Array.from(blob!)).toEqual([9, 8]);
  });

  it('passes queries and searches through unchanged', async () => {
    const { channel, calls } = host({
      query: () => ({ subjects: ['x'], count: 1 }),
      search: () => ['y'],
    });
    const db = new NativeClientDb(channel);

    expect(await db.query({ property: 'p', value: 'v', limit: 5 })).toEqual({
      subjects: ['x'],
      count: 1,
    });
    expect(await db.search('zebra', { limit: 3, parents: 'drive' })).toEqual([
      'y',
    ]);
    expect(calls[0]).toEqual([
      'query',
      [{ property: 'p', value: 'v', limit: 5 }],
    ]);
    expect(calls[1]).toEqual([
      'search',
      ['zebra', { limit: 3, parents: 'drive' }],
    ]);
  });
});

describe('NativeCryptoProvider', () => {
  it('signs through the host and caches the public key', async () => {
    const { channel, calls } = host({
      sign: ([data]) => `sig(${data})`,
      signBytes: () => 'bytesig',
      publicKey: () => 'PUB',
    });
    const crypto = new NativeCryptoProvider(channel);

    expect(crypto.signsDeterministically).toBe(true);
    expect(await crypto.sign('hello')).toBe('sig(hello)');
    expect(await crypto.signBytes(new Uint8Array([7]))).toBe('bytesig');
    expect(await crypto.getPublicKey()).toBe('PUB');
    expect(await crypto.getPublicKey()).toBe('PUB');
    expect(calls.filter(([m]) => m === 'publicKey')).toHaveLength(1);
    expect(calls.find(([m]) => m === 'signBytes')![1]).toEqual([
      encodeB64(new Uint8Array([7])),
    ]);
  });
});
