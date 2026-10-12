import { mkdtemp, readFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { Bridge, runBridge } from './bridge.js';
import {
  configPath,
  connect,
  loadConnection,
  normalizeServer,
  pkcePair,
} from './oauth.js';
import { startFakeNode, type FakeNode } from './test-node.js';

let node: FakeNode;

beforeAll(async () => {
  node = await startFakeNode();
});

afterAll(() => node.close());

beforeEach(async () => {
  process.env.XDG_CONFIG_HOME = await mkdtemp(
    path.join(tmpdir(), 'atomic-mcp-'),
  );
  node.requests.length = 0;
  node.valid.clear();
});

/** Plays the person: opens the link, clicks Allow, and the browser comes back. */
const personAllows = (link: string) => {
  void fetch(node.approve(link));
};

const connected = () =>
  connect({
    server: node.origin,
    clientName: 'Test machine',
    write: true,
    openUrl: personAllows,
  });

const lines = async (messages: object[], bridge: Bridge) => {
  const out: string[] = [];
  await runBridge(
    bridge,
    Readable.from(messages.map(m => `${JSON.stringify(m)}\n`)),
    { write: chunk => out.push(String(chunk)) },
  );

  return out.map(line => JSON.parse(line));
};

describe('connect', () => {
  it('registers, waits for the approval and keeps the token in a private file', async () => {
    const connection = await connected();

    expect(connection.scope).toBe('read write');
    expect(await loadConnection(node.origin)).toMatchObject({
      server: node.origin,
      clientId: 'client-1',
      refreshToken: 'refresh-1',
    });
    expect((await stat(configPath(node.origin))).mode & 0o077).toBe(0);

    const authorize = node.requests.find(r => r.path === '/oauth/register');
    expect(JSON.parse(authorize!.body).redirect_uris[0]).toMatch(
      /^http:\/\/127\.0\.0\.1:\d+\/callback$/,
    );
    // The token request names the node's /mcp as the resource.
    const token = node.requests.find(r => r.path === '/oauth/token')!;
    expect(new URLSearchParams(token.body).get('resource')).toBe(
      `${node.origin}/mcp`,
    );
  });

  it('refuses an answer for another request or from another server', async () => {
    await expect(
      connect({
        server: node.origin,
        clientName: 'x',
        write: false,
        openUrl: link => {
          const back = new URL(node.approve(link));
          back.searchParams.set('state', 'forged');
          void fetch(back.href);
        },
      }),
    ).rejects.toThrow(/did not match/);

    await expect(
      connect({
        server: node.origin,
        clientName: 'x',
        write: false,
        openUrl: link => {
          const back = new URL(node.approve(link));
          back.searchParams.set('iss', 'https://evil.example');
          void fetch(back.href);
        },
      }),
    ).rejects.toThrow(/another server/);
  });

  it('hands the desktop app what its consent page needs, with --desktop', async () => {
    let opened = '';

    await expect(
      connect({
        server: node.origin,
        clientName: 'Desk',
        write: true,
        desktop: true,
        timeoutMs: 50,
        openUrl: link => {
          opened = link;
        },
      }),
    ).rejects.toThrow(/Gave up/);

    const url = new URL(opened);
    expect(url.protocol).toBe('atomic:');
    expect(url.host).toBe('authorize-mcp');
    expect(url.searchParams.get('server')).toBe(node.origin);
    expect(url.searchParams.get('client_name')).toBe('Desk');
    expect(url.searchParams.get('scope')).toBe('read write');
    expect(url.searchParams.get('redirect_uri')).toMatch(
      /^http:\/\/127\.0\.0\.1:\d+\/callback$/,
    );
    expect(url.searchParams.get('code_challenge')).toBeTruthy();
    expect(url.searchParams.get('state')).toBeTruthy();
  });

  it('gives up after the timeout', async () => {
    await expect(
      connect({
        server: node.origin,
        clientName: 'x',
        write: false,
        timeoutMs: 50,
        openUrl: () => undefined,
      }),
    ).rejects.toThrow(/Gave up/);
  });

  it('does not leak a rejection when the timeout fires before anyone waits', async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);
    process.on('unhandledRejection', onUnhandled);

    await expect(
      connect({
        server: node.origin,
        clientName: 'x',
        write: false,
        timeoutMs: 10,
        // Registration outlasts the timeout, so `done` rejects unobserved.
        fetch: async (input, init) => {
          if (init?.method === 'POST') {
            await new Promise(resolve => setTimeout(resolve, 60));
          }

          return fetch(input, init);
        },
        openUrl: () => undefined,
      }),
    ).rejects.toThrow(/Gave up/);
    await new Promise(resolve => setTimeout(resolve, 20));
    process.off('unhandledRejection', onUnhandled);

    expect(unhandled).toEqual([]);
  });

  it('makes PKCE pairs and normalizes servers', () => {
    const { verifier, challenge } = pkcePair();
    expect(verifier).not.toBe(challenge);
    expect(normalizeServer('https://example.com/')).toBe('https://example.com');
    expect(() => normalizeServer('ftp://example.com')).toThrow();
  });
});

describe('bridge', () => {
  it('forwards messages with the token and drops nothing', async () => {
    await connected();
    const out = await lines(
      [
        { jsonrpc: '2.0', id: 1, method: 'tools/list' },
        { jsonrpc: '2.0', method: 'notifications/initialized' },
        { jsonrpc: '2.0', id: 2, method: 'tools/call', params: {} },
      ],
      new Bridge(node.origin),
    );

    expect(out.map(o => o.result.echoed).sort()).toEqual([
      'tools/call',
      'tools/list',
    ]);
    const mcp = node.requests.filter(r => r.path === '/mcp');
    expect(mcp).toHaveLength(3);
    expect(mcp.every(r => r.auth?.startsWith('Bearer access-'))).toBe(true);
  });

  it('renews an access token the node no longer accepts, once', async () => {
    await connected();
    node.valid.clear();
    const out = await lines(
      [{ jsonrpc: '2.0', id: 1, method: 'ping' }],
      new Bridge(node.origin),
    );

    expect(out[0].result.echoed).toBe('ping');
    expect(node.requests.filter(r => r.path === '/oauth/token').length).toBe(2); // the connect, and one refresh
    expect(
      JSON.parse(await readFile(configPath(node.origin), 'utf8')).accessToken,
    ).toMatch(/^access-/);
  });

  it('tells the assistant what to ask for when nothing is connected', async () => {
    const out = await lines(
      [
        { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
        { jsonrpc: '2.0', id: 2, method: 'tools/list' },
        {
          jsonrpc: '2.0',
          id: 3,
          method: 'tools/call',
          params: { name: 'connect_atomic' },
        },
      ],
      new Bridge(node.origin),
    );

    expect(out[0].result.instructions).toMatch(/connect/);
    expect(out[1].result.tools[0].name).toBe('connect_atomic');
    expect(out[2].result.isError).toBe(true);
    expect(out[2].result.content[0].text).toMatch(/npx -y @tomic\/mcp connect/);
    // Nothing reached the node.
    expect(node.requests.filter(r => r.path === '/mcp')).toHaveLength(0);
  });

  it('reports a revoked connection instead of hanging', async () => {
    await connected();
    // The node forgets the refresh token (revoked).
    const bridge = new Bridge(node.origin, (async (
      url: string,
      init: RequestInit,
    ) => {
      if (String(url).endsWith('/oauth/token')) {
        return new Response('{"error":"invalid_grant"}', { status: 400 });
      }

      return fetch(url, init);
    }) as typeof fetch);
    node.valid.clear();
    const out = await lines(
      [
        {
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'search' },
        },
      ],
      bridge,
    );

    expect(out[0].result.isError).toBe(true);
    expect(out[0].result.content[0].text).toMatch(/connect/);
  });
});
