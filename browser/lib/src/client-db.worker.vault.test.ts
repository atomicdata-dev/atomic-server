import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { WorkerRequest, WorkerResponse } from './client-db.worker.js';

const mocks = vi.hoisted(() => ({ flush: vi.fn(), vaultImport: vi.fn() }));
vi.mock('./client-db-open.js', () => ({
  openClientDb: async () => ({ db: mocks }),
  isStorageBlockedDbError: () => false,
}));
vi.mock('./wasm-url.js', () => ({
  default: async () => {},
  wasmBinaryUrl: () => 'unused.wasm',
}));

let worker: {
  onmessage: (event: { data: WorkerRequest }) => void;
  postMessage: (response: WorkerResponse) => void;
};
let nextId = 0;
type Request = Extract<WorkerRequest, { type: 'init' | 'vaultImport' }>;
type WithoutId<T> = T extends unknown ? Omit<T, 'id'> : never;

function send(message: WithoutId<Request>): Promise<WorkerResponse> {
  const id = ++nextId;

  return new Promise(resolve => {
    worker.postMessage = response => {
      if (response.id === id) resolve(response);
    };

    worker.onmessage({ data: { ...message, id } as WorkerRequest });
  });
}

const request = {
  type: 'vaultImport' as const,
  key: new Uint8Array(32),
  keyEpoch: 1,
  drivePseudonym: 'vault',
  devicePubkey: 'device',
  objects: [],
};
const summary = { resourcesRestored: 2, packsRead: 1, objectsUnreadable: 0 };

beforeEach(async () => {
  vi.resetModules();
  vi.resetAllMocks();
  vi.useFakeTimers();
  worker = { onmessage: () => {}, postMessage: () => {} };
  vi.stubGlobal('self', worker);
  mocks.vaultImport.mockResolvedValue(summary);
  await import('./client-db.worker.js');
  expect(await send({ type: 'init', wasmUrl: './wasm-url.js' })).toMatchObject({
    type: 'ok',
  });
});
afterEach(() => {
  vi.clearAllTimers();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

it('returns an error if restored data could not be made durable, then retries the flush', async () => {
  mocks.flush.mockImplementationOnce(() => {
    throw new Error('disk full');
  });
  vi.spyOn(console, 'error').mockImplementation(() => {});
  expect(await send(request)).toMatchObject({
    type: 'error',
    message: 'disk full',
  });
  await vi.advanceTimersByTimeAsync(1000);
  expect(mocks.flush).toHaveBeenCalledTimes(2);
});

it('acknowledges restore only after import and flush complete', async () => {
  const order: string[] = [];
  mocks.vaultImport.mockImplementation(async () => {
    order.push('import');

    return summary;
  });
  mocks.flush.mockImplementation(() => {
    order.push('flush');
  });
  expect(await send(request)).toMatchObject({ type: 'ok', data: summary });
  expect(order).toEqual(['import', 'flush']);
});

it('does not acknowledge or flush a rejected import', async () => {
  mocks.vaultImport.mockRejectedValue(new Error('invalid backup'));
  expect(await send(request)).toMatchObject({
    type: 'error',
    message: 'invalid backup',
  });
  expect(mocks.flush).not.toHaveBeenCalled();
});
