import { describe, it, expect, vi } from 'vitest';

import { ClientDbWorker } from './client-db.js';

describe('ClientDbWorker without a secure context', () => {
  it('parks in server-only mode with a clear error when Web Locks are unavailable', async () => {
    // Simulate an insecure context (plain HTTP on a non-localhost origin, e.g.
    // `http://homeassistant.local:9883`): the browser withholds
    // `navigator.locks`. Node's default test env already lacks it; make the
    // precondition explicit and robust to future Node versions that might add
    // it.
    if (
      typeof navigator !== 'undefined' &&
      (navigator as Navigator & { locks?: unknown }).locks
    ) {
      Object.defineProperty(navigator, 'locks', {
        value: undefined,
        configurable: true,
      });
    }

    const db = new ClientDbWorker('wasm-url', 'worker-url');

    // Must NOT throw an opaque TypeError — it resolves cleanly into a degraded,
    // server-only mode, recording the reason on `initError`.
    await expect(
      db.init('http://homeassistant.local:9883'),
    ).resolves.toBeUndefined();
    expect(db.initError).toBeInstanceOf(Error);
    expect(db.initError?.message).toMatch(/insecure connection/i);
  });
});

describe('ClientDbWorker cold initialization', () => {
  it('does not steal its own lock while its worker is still loading', async () => {
    vi.useFakeTimers();
    const request = vi.fn((_name, _options, callback) => callback());
    vi.stubGlobal('navigator', { locks: { request } });
    vi.stubGlobal(
      'BroadcastChannel',
      class {
        postMessage() {}
        close() {}
      },
    );
    vi.stubGlobal(
      'Worker',
      class {
        onmessage?: (event: unknown) => void;
        postMessage(message: { id: string }) {
          setTimeout(
            () =>
              this.onmessage?.({ data: { id: message.id, type: 'result' } }),
            3000,
          );
        }
        terminate() {}
      },
    );
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const db = new ClientDbWorker('wasm-url', 'worker-url');

    try {
      const initialized = db.init('https://example.com');
      await vi.advanceTimersByTimeAsync(3100);
      await initialized;
      expect(request).toHaveBeenCalledTimes(1);
      expect(warn).not.toHaveBeenCalled();
    } finally {
      db.destroy();
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
      vi.useRealTimers();
    }
  });
});
