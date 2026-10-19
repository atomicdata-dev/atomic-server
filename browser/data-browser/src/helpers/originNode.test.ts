import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  isOriginWithoutNode,
  originMayLackNode,
  probeOriginForNode,
  recallOriginProbe,
  rememberOriginWithoutNode,
} from './originNode';
import { serverProps } from './serverOntology';

const ORIGIN = 'https://app.example';

function respond(status: number, body: string, json = true) {
  return vi.fn(async () => ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => {
      if (!json) throw new SyntaxError('not JSON');

      return JSON.parse(body);
    },
  }));
}

describe('probeOriginForNode', () => {
  beforeEach(() => {
    rememberOriginWithoutNode(undefined);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it('a node answering /server with its version stays a node', async () => {
    vi.stubGlobal(
      'fetch',
      respond(200, JSON.stringify({ [serverProps.version]: '0.41.0' })),
    );

    await probeOriginForNode(ORIGIN);

    expect(isOriginWithoutNode(ORIGIN)).toBe(false);
  });

  it('a static host serving index.html for /server is not a node', async () => {
    // What the managed shared app origin actually does: SPA fallback.
    vi.stubGlobal('fetch', respond(200, '<!doctype html>', false));

    await probeOriginForNode(ORIGIN);

    expect(isOriginWithoutNode(ORIGIN)).toBe(true);
    // Any URL on that origin, not just the exact string that was probed.
    expect(isOriginWithoutNode(`${ORIGIN}/app/welcome`)).toBe(true);
    expect(isOriginWithoutNode('https://node1.example')).toBe(false);
  });

  it('a 404 is not a node either', async () => {
    vi.stubGlobal('fetch', respond(404, ''));

    await probeOriginForNode(ORIGIN);

    expect(isOriginWithoutNode(ORIGIN)).toBe(true);
  });

  it('JSON without a version or node id is not a node', async () => {
    vi.stubGlobal('fetch', respond(200, JSON.stringify({ hello: 'world' })));

    await probeOriginForNode(ORIGIN);

    expect(isOriginWithoutNode(ORIGIN)).toBe(true);
  });

  it('no answer at all leaves the default alone', async () => {
    // Offline is "server unreachable", not "there is no server" — a
    // node-served install reopened without network must keep reconnecting.
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch');
      }),
    );

    await probeOriginForNode(ORIGIN);

    expect(isOriginWithoutNode(ORIGIN)).toBe(false);
  });

  it('a server error is not a verdict', async () => {
    vi.stubGlobal('fetch', respond(502, ''));

    await probeOriginForNode(ORIGIN);

    expect(isOriginWithoutNode(ORIGIN)).toBe(false);
  });
});

describe('recallOriginProbe', () => {
  beforeEach(() => {
    rememberOriginWithoutNode(undefined);
    const data = new Map<string, string>();
    vi.stubGlobal('localStorage', {
      getItem: (k: string) => data.get(k) ?? null,
      setItem: (k: string, v: string) => void data.set(k, v),
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('knows nothing on a first visit', () => {
    expect(recallOriginProbe(ORIGIN)).toBe(false);
    expect(isOriginWithoutNode(ORIGIN)).toBe(false);
  });

  it('uses the last answer at once, and the probe corrects it', async () => {
    vi.stubGlobal('fetch', respond(404, ''));
    await probeOriginForNode(ORIGIN);

    rememberOriginWithoutNode(undefined);
    expect(recallOriginProbe(ORIGIN)).toBe(true);
    expect(isOriginWithoutNode(ORIGIN)).toBe(true);

    // The origin became a node since: the background probe says so.
    vi.stubGlobal(
      'fetch',
      respond(200, JSON.stringify({ [serverProps.version]: '0.41.0' })),
    );
    await probeOriginForNode(ORIGIN);
    expect(isOriginWithoutNode(ORIGIN)).toBe(false);

    rememberOriginWithoutNode(undefined);
    expect(recallOriginProbe(ORIGIN)).toBe(true);
    expect(isOriginWithoutNode(ORIGIN)).toBe(false);
  });

  it('a probe without an answer keeps the memo', async () => {
    vi.stubGlobal('fetch', respond(404, ''));
    await probeOriginForNode(ORIGIN);
    vi.stubGlobal('fetch', respond(502, ''));
    await probeOriginForNode(ORIGIN);
    rememberOriginWithoutNode(undefined);

    expect(recallOriginProbe(ORIGIN)).toBe(true);
    expect(isOriginWithoutNode(ORIGIN)).toBe(true);
  });
});

describe('originMayLackNode', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('only the hosted distribution probes its own origin', () => {
    vi.stubEnv('VITE_ATOMIC_HOSTED_DISTRIBUTION', '');
    expect(originMayLackNode()).toBe(false);

    vi.stubEnv('VITE_ATOMIC_HOSTED_DISTRIBUTION', '1');
    expect(originMayLackNode()).toBe(true);
  });
});
