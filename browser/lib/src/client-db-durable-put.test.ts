import { afterEach, expect, it, vi } from 'vitest';

const db = vi.hoisted(() => ({
  putResource: vi.fn(),
  putResourceWithSnapshot: vi.fn(),
  outboxWrite: vi.fn(),
  putBlob: vi.fn(),
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

it.each(
  ['snapshot', 'blob'].flatMap(kind =>
    [false, true].map(fail => ({ kind, fail })),
  ),
)(
  '$kind acknowledges durability or reports its flush failure ($fail)',
  async ({ kind, fail }) => {
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
    db.putResourceWithSnapshot.mockImplementation(async () => {
      order.push('properties and snapshot');
    });
    db.flush.mockImplementation(() => {
      order.push('flush');
      if (fail) throw new Error('disk unavailable');
    });
    db.putBlob.mockImplementation(() => {
      order.push('blob');
    });
    const response = await send(
      kind === 'blob'
        ? {
            type: 'putBlob',
            hash: new Uint8Array(32),
            data: new Uint8Array([1]),
          }
        : {
            type: 'putResourceWithSnapshot',
            subject: 'did:ad:test',
            jsonAd: '{"@id":"did:ad:test"}',
            snapshot: new Uint8Array([1]),
          },
    );
    expect(order).toEqual(
      kind === 'blob'
        ? ['blob', 'flush']
        : ['properties and snapshot', 'flush'],
    );
    expect(db.putResource).not.toHaveBeenCalled();
    expect(response.type).toBe(fail ? 'error' : 'ok');
    if (fail) expect(response.message).toBe('disk unavailable');

    // A failed durability barrier still gets a background retry. Successful
    // writes do not schedule an additional fsync one second later.
    db.flush.mockImplementation(() => {});
    await vi.advanceTimersByTimeAsync(1000);
    expect(db.flush).toHaveBeenCalledTimes(fail ? 2 : 1);
  },
);

it('writes an outbox row with its snapshot under the same flush', async () => {
  vi.useFakeTimers();
  const responses = new Map<number, (value: Record<string, unknown>) => void>();
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
  db.putResourceWithSnapshot.mockImplementation(async () => {
    order.push('snapshot');
  });
  db.outboxWrite.mockImplementation((agent, puts, deletes) => {
    order.push(`outbox ${agent} ${puts} ${deletes}`);
  });
  db.flush.mockImplementation(() => order.push('flush'));
  const outbox = {
    agent: 'did:ad:agent:a',
    puts: [{ subject: 'did:ad:test', value: '{}' }],
    deletes: [],
  };

  await send({
    type: 'putResourceWithSnapshot',
    subject: 'did:ad:test',
    jsonAd: '{"@id":"did:ad:test"}',
    snapshot: new Uint8Array([1]),
    outbox,
  });
  expect(order).toEqual([
    'snapshot',
    `outbox did:ad:agent:a ${JSON.stringify(outbox.puts)} []`,
    'flush',
  ]);

  // A plain dirty bit waits for the tick; an envelope is flushed at once.
  order.length = 0;
  await send({ type: 'outboxWrite', ...outbox, durable: false });
  expect(order).toHaveLength(1);
  await vi.advanceTimersByTimeAsync(1000);
  expect(order.at(-1)).toBe('flush');

  order.length = 0;
  await send({ type: 'outboxWrite', ...outbox, durable: true });
  expect(order.at(-1)).toBe('flush');
});
