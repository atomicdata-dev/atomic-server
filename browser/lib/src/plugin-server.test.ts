import { afterEach, expect, it, vi } from 'vitest';
import { executeServerPlugin } from './plugin-server.js';
vi.mock('./authentication.js', () => ({
  signRequest: async () => ({ 'x-test-signature': 'signed' }),
}));
afterEach(() => vi.unstubAllGlobals());
const store = {
  getAgent: () => ({}),
  getServerUrl: () => 'http://localhost:9898',
} as Parameters<typeof executeServerPlugin>[0];
const request = {
  drive: 'drive',
  plugin: 'plugin',
  source: 'export function run() {}',
  input: { phase: 'discover' },
};
it('uses the signed shared runtime endpoint and preserves plugin output', async () => {
  const fetch = vi.fn(async (_url, init) => {
    expect(init.headers['x-test-signature']).toBe('signed');
    expect(JSON.parse(init.body)).toEqual({
      ...request,
      input: JSON.stringify(request.input),
    });

    return Response.json({ verdict: '{"discovery":{}}', error: null });
  });
  vi.stubGlobal('fetch', fetch);
  expect(await executeServerPlugin(store, request)).toEqual({
    verdict: '{"discovery":{}}',
    error: null,
  });
  expect(fetch.mock.calls[0][0]).toBe('http://localhost:9898/plugin-run');
});
it('preserves sandbox errors and rejects malformed responses and HTTP failures', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      Response.json({ verdict: null, error: 'Clockify unavailable' }),
    ),
  );
  expect((await executeServerPlugin(store, request)).error).toBe(
    'Clockify unavailable',
  );
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json({ verdict: {} })),
  );
  await expect(executeServerPlugin(store, request)).rejects.toThrow(
    'Invalid plugin runtime response',
  );
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response('denied', { status: 403 })),
  );
  await expect(executeServerPlugin(store, request)).rejects.toThrow();
});
it('does not send credentials or requests when signed out', async () => {
  const fetch = vi.fn();
  vi.stubGlobal('fetch', fetch);
  await expect(
    executeServerPlugin({ ...store, getAgent: () => undefined }, request),
  ).rejects.toThrow('Not signed in');
  expect(fetch).not.toHaveBeenCalled();
});
