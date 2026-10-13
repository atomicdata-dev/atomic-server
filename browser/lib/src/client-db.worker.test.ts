import { afterEach, expect, it, vi } from 'vitest';

const db = vi.hoisted(() => ({
  vaultCommitSegment: vi.fn(),
  vaultImport: vi.fn(),
  flush: vi.fn(),
}));
vi.mock('./client-db-open.js', () => ({
  openClientDb: async () => ({ db }),
  isStorageBlockedDbError: () => false,
}));

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  vi.resetModules();
  vi.resetAllMocks();
});

it.each([
  ['vaultCommitSegment', false],
  ['vaultCommitSegment', true],
  ['vaultImport', false],
  ['vaultImport', true],
] as const)(
  'acknowledges %s only after durable flush (failure=%s)',
  async (type, fail) => {
    vi.useFakeTimers();
    const worker = {
      onmessage: null as unknown as (event: unknown) => void,
      postMessage: vi.fn(),
    };
    vi.stubGlobal('self', worker);
    await import('./client-db.worker.js');
    let id = 0;

    async function send(message: object) {
      const requestId = ++id;
      const response = new Promise<Record<string, unknown>>(resolve => {
        worker.postMessage.mockImplementation(value => {
          if (value.id === requestId) resolve(value);
        });
      });
      worker.onmessage({ data: { ...message, id: requestId } });

      return response;
    }

    await send({
      type: 'init',
      wasmUrl: 'data:text/javascript,export default async function() {}',
    });
    const order: string[] = [];
    db.vaultCommitSegment.mockImplementation(() => order.push('commit'));
    const summary = { resourcesRestored: 3, objectsUnreadable: 0 };
    db.vaultImport.mockImplementation(async () => {
      order.push('import');

      return summary;
    });
    db.flush.mockImplementation(() => {
      order.push('flush');
      if (fail) throw new Error('disk unavailable');
    });
    // No timer advances: a reload can kill the worker before its periodic tick.
    const response = await send({
      type,
      drivePseudonym: 'drive',
      devicePubkey: 'device',
      segment: 1,
    });
    expect(order).toEqual([
      type === 'vaultImport' ? 'import' : 'commit',
      'flush',
    ]);
    expect(response.type).toBe(fail ? 'error' : 'ok');

    if (fail) {
      expect(response.message).toBe('disk unavailable');
      // The failed acknowledgement must leave the worker usable for retry.
      db.flush.mockImplementation(() => order.push('retry flush'));
      const retry = await send({
        type,
        drivePseudonym: 'drive',
        devicePubkey: 'device',
        segment: 1,
      });
      expect(retry.type).toBe('ok');
      expect(order.at(-1)).toBe('retry flush');
    } else if (type === 'vaultImport') {
      expect(response.data).toEqual(summary);
    }
  },
);
