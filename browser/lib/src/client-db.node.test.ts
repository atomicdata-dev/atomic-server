import { expect, it, vi } from 'vitest';
import { NodeClientDb } from './client-db.node.js';

it.each(['snapshot', 'envelopes', 'import'] as const)(
  'does not expose the temporary snapshot between JSON and causal-state writes during %s',
  async operation => {
    let release!: () => void;
    const gate = new Promise<void>(resolve => {
      release = resolve;
    });
    let snapshot: Uint8Array = new Uint8Array([0]);
    // The JSON row and the causal state land in steps; a read queued behind
    // the write must not observe the intermediate state.
    const putResourceWithSnapshot = vi.fn(
      async (_jsonAd: string, value: Uint8Array) => {
        snapshot = new Uint8Array([1]);
        await gate;
        snapshot = value;
      },
    );
    const adapter = new NodeClientDb({ wasmPath: 'unused-in-unit-test' });
    Object.assign(adapter, {
      db: {
        putResourceWithSnapshot,
        getResourceWithSnapshot: async () => ({
          jsonAd: '{"@id":"did:ad:test"}',
          snapshot,
        }),
        getLoroSnapshot: () => snapshot,
        envelopesFor: () => JSON.stringify({ snapshot: [...snapshot] }),
        importEnvelopes: async () => snapshot[0],
      },
    });
    const write = adapter.putResourceWithSnapshot(
      'did:ad:test',
      '{}',
      new Uint8Array([2]),
    );
    await vi.waitFor(() => expect(putResourceWithSnapshot).toHaveBeenCalled());
    let readSettled = false;
    const pending =
      operation === 'snapshot'
        ? adapter.getResourceWithSnapshot('did:ad:test')
        : operation === 'envelopes'
          ? adapter.envelopesFor(['did:ad:test'])
          : adapter.importEnvelopes([{ subject: 'did:ad:test', json: '{}' }]);
    const read = pending.then(result => {
      readSettled = true;

      return result;
    });
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(readSettled).toBe(false);
    release();
    await write;
    const result = await read;
    if (operation === 'snapshot')
      expect(result).toMatchObject({ snapshot: new Uint8Array([2]) });
    else if (operation === 'envelopes')
      expect(result).toEqual({ snapshot: [2] });
    else expect(result).toBe(2);
  },
);
