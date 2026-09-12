import { describe, it, vi, afterEach } from 'vitest';
import { randomUUID } from './random-uuid.js';

const V4 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('randomUUID', () => {
  it('produces a v4 uuid', ({ expect }) => {
    expect(randomUUID()).toMatch(V4);
  });

  /**
   * The whole point: over plain HTTP on a LAN — `http://homeassistant.local`,
   * `http://192.168.1.x` — the context is insecure and `crypto.randomUUID` is
   * simply absent. `getRandomValues` is not gated, so we can still answer.
   */
  it('works where crypto.randomUUID does not exist', ({ expect }) => {
    const real = globalThis.crypto;
    vi.stubGlobal('crypto', {
      getRandomValues: <T extends ArrayBufferView | null>(a: T): T =>
        real.getRandomValues(a as never) as T,
    });

    expect(globalThis.crypto.randomUUID).toBeUndefined();
    expect(randomUUID()).toMatch(V4);
  });

  it('does not repeat itself', ({ expect }) => {
    const seen = new Set(Array.from({ length: 500 }, () => randomUUID()));
    expect(seen.size).toBe(500);
  });
});
