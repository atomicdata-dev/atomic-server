import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.doUnmock('loro-crdt/web');
});

describe('WASM initialization during navigation', () => {
  it.each([false, true])('discarded document = %s', async discarded => {
    vi.resetModules();
    const page = Object.assign(new EventTarget(), { document: {} });
    vi.stubGlobal('window', page);
    let reject!: (error: Error) => void;
    const init = vi.fn(
      () =>
        new Promise((_resolve, fail) => {
          reject = fail;
        }),
    );
    vi.doMock('loro-crdt/web', () => ({ default: init }));
    const { LoroLoader } = await import('./loro-loader.js');
    const loading = LoroLoader.initializeLoro();
    const result = loading.then(
      () => 'finished',
      () => 'failed',
    );
    await vi.waitFor(() => expect(init).toHaveBeenCalled());
    if (discarded) page.dispatchEvent(new Event('pagehide'));
    reject(new TypeError('Response body loading was aborted'));
    expect(await result).toBe(discarded ? 'finished' : 'failed');
    expect(LoroLoader.isLoaded()).toBe(false);
  });
});
