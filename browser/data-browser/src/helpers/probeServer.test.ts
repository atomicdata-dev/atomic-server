import { afterEach, describe, expect, it, vi } from 'vitest';
import { probeServer } from './probeServer';
import { serverProps } from './serverOntology';

function respond(body: string, init: ResponseInit = { status: 200 }) {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(body, init)));
}

describe('probeServer', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('accepts node JSON', async () => {
    respond(JSON.stringify({ [serverProps.version]: '0.40.0' }));
    expect(await probeServer('https://node.example')).toBe('node');
  });

  it('rejects HTML served for every path', async () => {
    respond('<!doctype html><html></html>', {
      status: 200,
      headers: { 'Content-Type': 'text/html' },
    });
    expect(await probeServer('https://site.example')).toBe('not-node');
  });

  it('rejects JSON that is not node info and error statuses', async () => {
    respond('{"hello":"world"}');
    expect(await probeServer('https://x.example')).toBe('not-node');
    respond('nope', { status: 404 });
    expect(await probeServer('https://x.example')).toBe('not-node');
  });

  it('reports a network error as unreachable', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('failed')));
    expect(await probeServer('https://down.example')).toBe('unreachable');
  });

  it('does not follow redirects', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new TypeError('redirect'));

    vi.stubGlobal('fetch', fetchMock);
    expect(await probeServer('https://node.example')).toBe('unreachable');
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ redirect: 'error' });
  });
});
