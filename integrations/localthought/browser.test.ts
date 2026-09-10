import { afterEach, expect, it, vi } from 'vitest';
import { BrowserIntegrations, mergeQuerySelections, proxyOrigin, sign, type Engine, type ImportLimits } from './browser';
const secret = 'bW9jay10ZW5hbnQ.mock-signature';
const origin = 'https://proxy.example';
function setup(policy?: Partial<ImportLimits>, sleep?: (milliseconds: number) => Promise<void>) {
  const values = new Map<string, string>();
  const storage = {
    getItem: (k: string) => values.get(k) ?? null,
    setItem: (k: string, v: string) => {
      values.set(k, v);
    },
  } as Storage;
  vi.stubGlobal('location', { origin: 'https://atomic.example' });
  vi.stubGlobal('navigator', {
    locks: { request: (_: string, f: () => unknown) => f() },
  });
  const http = vi.fn(async (url: string, init?: RequestInit) => {
    expect(init?.credentials).toBe('omit');
    expect(init?.redirect).toBe('error');
    if (url.endsWith('/catalog')) return new Response('["pets"]');
    if (url.endsWith('/session'))
      return Response.json({ ts: 1, nonce: 'nonce', challenge: 'challenge' });
    return new Response('{}');
  });
  const engine: Engine = {
    describeIntegration: async () =>
      JSON.stringify({
        upstream: 'https://pets.example',
      }),
    fetchIntegration: async (_text, _platform, _constants, _range, fetch) => {
      const first = JSON.parse(await fetch('https://pets.example/pets'));
      expect(first.headers['x-connection-code']).toBeUndefined();
      await fetch('https://pets.example/pets?page=2');
      return '{"records":[]}';
    },
  };
  const client = new BrowserIntegrations(
    storage,
    async () => engine,
    origin,
    http as typeof fetch,
    sleep,
    policy,
  );
  const start = () =>
    client.start(
      'drive',
      'actor',
      'pets',
      'https://atomic.example/app/integrations',
      secret,
    );
  return { values, storage, http, engine, client, start };
}

it('validates consumer import limits', async () => {
  const { client, start } = setup({ maxRequests: 0 });
  const { state } = await start();
  client.finish('drive', 'actor', state, 'first');
  await expect(client.fetchRecords('drive', 'actor', state, {})).rejects.toThrow(
    'Invalid import limits',
  );
  const defaultClient = setup().client;
  expect(defaultClient).toBeDefined();
});

it('merges catalog selections with explicit caller values winning', () => {
  expect(
    mergeQuerySelections(
      { query_overrides: [{ path: '/items', values: { active: false, archived: true } }] },
      { query_overrides: [{ path: '/items', values: { active: true } }, { path: '/other', values: { all: true } }] },
    ),
  ).toEqual({
    query_overrides: [
      { path: '/items', values: { active: true, archived: true } },
      { path: '/other', values: { all: true } },
    ],
  });
});

it('paces requests and permits a configured request budget', async () => {
  vi.spyOn(Date, 'now').mockReturnValue(1000);
  const waits: number[] = [];
  const { client, start, engine, http } = setup(
    { minRequestIntervalMs: 2100, maxRequests: 201, timeoutMs: 1800000 },
    async milliseconds => {
      waits.push(milliseconds);
    },
  );
  const { state } = await start();
  client.finish('drive', 'actor', state, 'first');
  let count = 0;
  http.mockImplementation(async (url, init) => {
    if (url.includes('/catalog/')) return new Response('{}');
    count++;
    return new Response('{}', {
      headers: { 'x-connection-code': `next-${count}` },
    });
  });
  engine.fetchIntegration = async (_t, _p, _c, _r, fetch) => {
    for (let i = 0; i < 201; i++) await fetch(`https://pets.example/pets?page=${i}`);
    return '{}';
  };
  await client.fetchRecords('drive', 'actor', state, {});
  expect(count).toBe(201);
  expect(waits).toHaveLength(200);
  expect(waits.every(value => value === 2100)).toBe(true);
});

it('honors Retry-After on 429 with a rotated code and bounded retry', async () => {
  const waits: number[] = [];
  const { client, start, engine, http } = setup(
    { maxRequests: 10, timeoutMs: 120000 },
    async milliseconds => waits.push(milliseconds),
  );
  const { state } = await start();
  client.finish('drive', 'actor', state, 'first');
  const codes: string[] = [];
  let call = 0;
  http.mockImplementation(async (url, init) => {
    if (url.includes('/catalog/')) return new Response('{}');
    codes.push((init?.headers as Record<string, string>).Authorization);
    call++;
    return new Response('{}', {
      status: call === 1 ? 429 : 200,
      headers: {
        'x-connection-code': call === 1 ? 'second' : 'third',
        ...(call === 1 ? { 'Retry-After': '2' } : {}),
      },
    });
  });
  engine.fetchIntegration = async (_t, _p, _c, _r, fetch) => {
    await fetch('https://pets.example/pets');
    return '{}';
  };
  await client.fetchRecords('drive', 'actor', state, {});
  expect(codes).toEqual(['Bearer first', 'Bearer second']);
  expect(waits).toEqual([2000]);
});
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });
it('matches the tenant HMAC protocol and rejects non-origin proxy URLs', async () => {
  expect(await sign('key', 'The quick brown fox jumps over the lazy dog')).toBe(
    '97yD9DBThCSxMpjmqm-xQ-9NWaFJRhdZl0edvC0aPNg',
  );
  expect(() => proxyOrigin('https://proxy.example/path')).toThrow();
  expect(() => proxyOrigin('http://proxy.example')).toThrow();
});
it('binds returns to actor, drive and expiry without saving tenant secrets', async () => {
  const { client, start, values } = setup();
  const { state, url } = await start();
  expect(url).not.toContain(secret);
  expect([...values.values()].join()).not.toContain(secret);
  expect(() => client.finish('other', 'actor', state, 'code')).toThrow();
  expect(() => client.finish('drive', 'other', state, 'code')).toThrow();
  expect(client.finish('drive', 'actor', state, 'code').platform).toBe('pets');
  expect(() => client.finish('drive', 'actor', state, 'code')).toThrow();
});
it('consumes before dispatch and preserves rotation and pagination', async () => {
  const { client, start, http, values } = setup();
  const { state } = await start();
  client.finish('drive', 'actor', state, 'first');
  const codes: string[] = [];
  http.mockImplementation(async (url, init) => {
    if (url.includes('/catalog/')) return new Response('{}');
    expect(JSON.parse([...values.values()][0]).code).toBeUndefined();
    codes.push((init?.headers as Record<string, string>).Authorization);
    return new Response('[]', {
      headers: {
        'x-connection-code': 'second',
        link: '<https://pets.example/pets?page=2>; rel=next',
      },
    });
  });
  await client.fetchRecords('drive', 'actor', state, {});
  expect(codes).toEqual(['Bearer first', 'Bearer second']);
  expect(http.mock.calls.at(-1)?.[0]).toBe(`${origin}/proxy/pets/pets?page=2`);
});
it('never retries an uncertain consumed credential', async () => {
  const { client, start, http } = setup();
  const { state } = await start();
  client.finish('drive', 'actor', state, 'first');
  http.mockImplementation(async url => {
    if (url.includes('/catalog/')) return new Response('{}');
    throw new Error('connection lost');
  });
  await expect(
    client.fetchRecords('drive', 'actor', state, {}),
  ).rejects.toThrow('lost');
  const calls = http.mock.calls.length;
  await expect(
    client.fetchRecords('drive', 'actor', state, {}),
  ).rejects.toThrow('Reconnect');
  expect(http.mock.calls).toHaveLength(calls);
});
it('rejects pagination to a different provider before spending a credential', async () => {
  const { client, start, engine, values } = setup();
  const { state } = await start();
  client.finish('drive', 'actor', state, 'first');
  engine.fetchIntegration = async (_t, _p, _c, _r, fetch) =>
    fetch('https://evil.example/pets');
  await expect(
    client.fetchRecords('drive', 'actor', state, {}),
  ).rejects.toThrow('origin');
  expect(JSON.parse([...values.values()][0]).code).toBe('first');
});

it('calls the browser fetch function without binding it to the client', async () => {
  const { storage, engine } = setup();
  vi.stubGlobal('fetch', function (this: unknown) {
    expect(this).not.toBeInstanceOf(BrowserIntegrations);
    return Promise.resolve(new Response('["pets"]'));
  });
  const client = new BrowserIntegrations(storage, async () => engine, origin);
  expect(await client.catalog()).toEqual(['pets']);
});

it('supports the demo callback and write credentials without using the import engine', async () => {
  const { client, http, values } = setup();
  const { state } = await client.start(
    'drive',
    'actor',
    'pets',
    'https://atomic.example/app/devonian-demo',
    secret,
  );
  client.finish('drive', 'actor', state, 'first');
  http.mockImplementation(async (_url, init) => {
    expect(JSON.parse([...values.values()][0]).code).toBeUndefined();
    expect(init?.method).toBe('POST');
    expect(init?.body).toBe('{"title":"new"}');
    return new Response('{"id":1}', {
      status: 201,
      headers: { 'X-Connection-Code': 'next' },
    });
  });
  await expect(
    client.request('drive', 'actor', state, 'github-issues', '/issues'),
  ).rejects.toThrow('another platform');
  await expect(
    client.request('drive', 'actor', state, 'pets', '//evil.example'),
  ).rejects.toThrow('Invalid proxy path');
  expect(
    await client.request('drive', 'actor', state, 'pets', '/issues', {
      method: 'POST',
      body: '{"title":"new"}',
    }),
  ).toEqual({ status: 201, body: '{"id":1}' });
  expect(JSON.parse([...values.values()][0]).code).toBe('next');
});
it('forwards the conditional event version while keeping authorization host-owned', async () => {
  const { client, start, http } = setup();
  const { state } = await start();
  client.finish('drive', 'actor', state, 'first');
  http.mockImplementation(async (_url, init) => {
    expect(init?.headers).toEqual({
      Authorization: 'Bearer first',
      'Content-Type': 'application/json',
      'If-Match': '"version"',
    });
    expect(init?.method).toBe('PATCH');
    expect(init?.body).toBe('{"summary":"Updated"}');
    return new Response('{}', { headers: { 'x-connection-code': 'next' } });
  });
  await client.request('drive', 'actor', state, 'pets', '/events/id', {
    method: 'PATCH',
    body: '{"summary":"Updated"}',
    ifMatch: '"version"',
  });
});

it('does not take consumer request budgets from an API description', async () => {
  const { client, start, engine, http } = setup();
  const { state } = await start();
  client.finish('drive', 'actor', state, 'first');
  engine.describeIntegration = async () => JSON.stringify({
    upstream: 'https://pets.example',
    importPolicy: { maxRequests: 1 },
    'x-import-policy': { timeoutMs: 1 },
  });
  let count = 0;
  http.mockImplementation(async url => {
    if (url.includes('/catalog/')) return new Response('{}');
    return new Response('{}', { headers: { 'x-connection-code': `next-${++count}` } });
  });
  await client.fetchRecords('drive', 'actor', state, {});
  expect(count).toBe(2);
});

it('rejects retry delays beyond the consumer deadline without sleeping', async () => {
  const sleep = vi.fn(async () => {});
  const { client, start, engine, http } = setup({ timeoutMs: 1000 }, sleep);
  const { state } = await start();
  client.finish('drive', 'actor', state, 'first');
  http.mockImplementation(async url => {
    if (url.includes('/catalog/')) return new Response('{}');
    return new Response('{}', { status: 429, headers: { 'x-connection-code': 'second', 'retry-after': '300' } });
  });
  await expect(client.fetchRecords('drive', 'actor', state, {})).rejects.toThrow('API retry delay exceeds remaining import time');
  expect(sleep).not.toHaveBeenCalled();
});
