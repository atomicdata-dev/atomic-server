import { afterEach, expect, it, vi } from 'vitest';

const db = vi.hoisted(() => ({
  putResource: vi.fn(),
  putLoroSnapshot: vi.fn(),
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

it.each([false, true])(
  'a snapshot write acknowledges durability or reports its flush failure (%s)',
  async fail => {
    vi.useFakeTimers();
    const responses = new Map<
      number,
      (value: Record<string, unknown>) => void
    >();
    const worker = {
      onmessage: null as unknown as (event: unknown) => void,
      postMessage: (value: Record<string, unknown>) => {
        responses.get(value.id as number)?.(value);
      },
    };
    vi.stubGlobal('self', worker);
    await import('./client-db.worker.js');
    let nextId = 0;

    const send = (request: object) => {
      const id = ++nextId;
      const response = new Promise<Record<string, unknown>>(resolve => {
        responses.set(id, resolve);
      });
      worker.onmessage({ data: { ...request, id } });

      return response;
    };

    await send({
      type: 'init',
      wasmUrl: 'data:text/javascript,export default async function() {}',
    });
    const order: string[] = [];
    db.putResource.mockImplementation(async () => {
      order.push('properties');
    });
    db.putLoroSnapshot.mockImplementation(() => {
      order.push('snapshot');
    });
    db.flush.mockImplementation(() => {
      order.push('flush');
      if (fail) throw new Error('disk unavailable');
    });
    const response = await send({
      type: 'putResourceWithSnapshot',
      subject: 'did:ad:test',
      jsonAd: '{"@id":"did:ad:test"}',
      snapshot: new Uint8Array([1]),
    });
    expect(order).toEqual(['properties', 'snapshot', 'flush']);
    expect(response.type).toBe(fail ? 'error' : 'ok');
    if (fail) expect(response.message).toBe('disk unavailable');

    // A failed durability barrier still gets a background retry. Successful
    // writes do not schedule an additional fsync one second later.
    db.flush.mockImplementation(() => {});
    await vi.advanceTimersByTimeAsync(1000);
    expect(db.flush).toHaveBeenCalledTimes(fail ? 2 : 1);
  },
);
