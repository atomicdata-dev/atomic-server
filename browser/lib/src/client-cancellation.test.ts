import { afterEach, describe, expect, it, vi } from 'vitest';
import { Client } from './client.js';
import { ErrorType } from './error.js';

afterEach(() => vi.unstubAllGlobals());

describe('page-owned HTTP reads', () => {
  it('cancels a pending read when its document is discarded', async () => {
    const page = new EventTarget();
    vi.stubGlobal('window', page);
    let started!: () => void;
    const ready = new Promise<void>(resolve => {
      started = resolve;
    });
    const client = new Client(
      vi.fn(
        (_url, opts) =>
          new Promise((_resolve, reject) => {
            opts?.signal?.addEventListener('abort', () =>
              reject(new DOMException('Aborted', 'AbortError')),
            );
            started();
          }),
      ) as typeof fetch,
    );
    const request = client.fetchResourceHTTP('https://example.com/resource');
    await ready;
    page.dispatchEvent(new Event('pagehide'));
    expect(await request).toMatchObject({
      cancelled: true,
      createdResources: [],
    });
  });

  it('still reports transport failures on an active page', async () => {
    vi.stubGlobal('window', new EventTarget());
    const client = new Client(
      vi.fn().mockRejectedValue(new TypeError('Failed to fetch')),
    );
    const result = await client.fetchResourceHTTP(
      'https://example.com/resource',
    );
    expect(result.cancelled).toBeUndefined();
    expect(result.resource.error).toMatchObject({ type: ErrorType.Transport });
  });
});
