import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { encodePairingEnvelope, type Agent } from '@tomic/lib';

// The embedded-server origin is a Tauri concern; the pairing logic only needs
// it to build a URL, so the real module (which touches `window`) stays out.
vi.mock('./tauri', () => ({
  getLocalServerOrigin: () => 'http://localhost:9883',
}));

const { runPairing, pairAndSync } = await import('./pairing');
const { readKnownPeers } = await import('./knownPeers');

const NODE = `did:ad:node:${'a'.repeat(64)}`;
const DRIVE = 'https://atomicdata.dev/drive/abc';

/**
 * Just enough agent for `signRequest`: the headers it produces are what the
 * server checks, and the real one needs a keypair and WebCrypto.
 */
const AGENT = {
  subject: 'did:ad:agent:abc',
  getPublicKey: async () => 'pk',
  createSignature: async () => 'sig',
} as unknown as Agent;

const AUTH_HEADERS = [
  'x-atomic-public-key',
  'x-atomic-signature',
  'x-atomic-timestamp',
  'x-atomic-agent',
];

function installLocalStorage() {
  const store = new Map<string, string>();

  globalThis.localStorage = {
    getItem: (key: string) => store.get(key) ?? null,
    setItem: (key: string, value: string) => void store.set(key, value),
    removeItem: (key: string) => void store.delete(key),
    clear: () => store.clear(),
    key: (index: number) => [...store.keys()][index] ?? null,
    get length() {
      return store.size;
    },
  } as Storage;
}

/** Stub `/iroh-sync` with whatever the embedded server would have answered. */
function stubIrohSync(body: unknown) {
  const fetchMock = vi.fn().mockResolvedValue({ json: async () => body });
  globalThis.fetch = fetchMock as unknown as typeof fetch;

  return fetchMock;
}

const validCode = encodePairingEnvelope({ v: 1, node: NODE, drives: '*' });

/**
 * The shared `POST /iroh-sync` contract. The Rust handler's test asserts it
 * *accepts* this exact body; the test below asserts this client *sends* it.
 * Without a shared artefact, renaming a field on either side keeps both suites
 * green and breaks pairing in production.
 */
const pairingContract = (() => {
  const path = fileURLToPath(
    new URL('../../../../testdata/pairing-request.json', import.meta.url),
  );
  const parsed = JSON.parse(readFileSync(path, 'utf-8')) as Record<
    string,
    unknown
  >;

  return Object.fromEntries(
    Object.entries(parsed).filter(([key]) => !key.startsWith('_')),
  );
})();

describe('pairAndSync', () => {
  beforeEach(() => {
    installLocalStorage();
    vi.restoreAllMocks();
  });

  it('records the peer and reports what reconciled', async () => {
    const fetchMock = stubIrohSync({ count: 7, peerName: 'Joep’s phone' });

    const outcome = await pairAndSync(NODE, DRIVE, AGENT);

    expect(outcome).toEqual({ count: 7, peerName: 'Joep’s phone' });
    expect(readKnownPeers()[0].nodeId).toBe(NODE);

    const [url, init] = fetchMock.mock.calls[0];
    // Absolute origin: a bare path would hit `tauri.localhost`, not the
    // embedded server, inside the desktop/mobile webview.
    expect(url).toBe('http://localhost:9883/iroh-sync');
    expect(JSON.parse(init.body)).toEqual({ nodeId: NODE, drive: DRIVE });
    // Signed over the exact URL: the server only dials a peer for an agent
    // with write rights on the drive, and rebuilds the signed subject from
    // the request it received.
    expect(init.headers['Content-Type']).toBe('application/json');

    for (const header of AUTH_HEADERS) {
      expect(init.headers[header], header).toBeTruthy();
    }

    expect(init.headers['x-atomic-agent']).toBe(AGENT.subject);
  });

  it('goes out unsigned without an agent, so the node’s refusal is what shows', async () => {
    const fetchMock = stubIrohSync({ error: 'unauthorized' });

    await expect(pairAndSync(NODE, DRIVE, undefined)).rejects.toThrow(
      'unauthorized',
    );

    const [, init] = fetchMock.mock.calls[0];

    for (const header of AUTH_HEADERS) {
      expect(init.headers[header], header).toBeUndefined();
    }
  });

  it('surfaces a refusal that carries no JSON body', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      status: 403,
      statusText: 'Forbidden',
      json: async () => {
        throw new SyntaxError('Unexpected end of JSON input');
      },
    }) as unknown as typeof fetch;

    await expect(pairAndSync(NODE, DRIVE, AGENT)).rejects.toThrow(
      '403 Forbidden',
    );
  });

  it('sends exactly the shared /iroh-sync contract', async () => {
    const fetchMock = stubIrohSync({ count: 1 });

    await pairAndSync(
      pairingContract.nodeId as string,
      pairingContract.drive as string,
      AGENT,
    );

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);

    // Field-for-field, not a subset: an extra or renamed key here is a request
    // the Rust handler has never been shown.
    expect(body).toEqual(pairingContract);
  });

  it('upgrades the peer label once the peer names itself', async () => {
    stubIrohSync({ count: 1, peerName: 'Tablet' });

    await pairAndSync(NODE, DRIVE, AGENT);

    expect(readKnownPeers()[0].label).toBe('Tablet');
  });

  it('still records the peer when there is no drive to sync yet', async () => {
    const fetchMock = stubIrohSync({ count: 0 });

    // A device that has not signed in yet has no drive. Recording the peer
    // anyway is the point: a later sync can use it.
    await expect(pairAndSync(NODE, undefined, AGENT)).resolves.toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(readKnownPeers()[0].nodeId).toBe(NODE);
  });

  it('throws the server-reported error', async () => {
    stubIrohSync({ error: 'no route to peer' });

    await expect(pairAndSync(NODE, DRIVE, AGENT)).rejects.toThrow(
      'no route to peer',
    );
  });

  it('treats a blank peer name as no name', async () => {
    stubIrohSync({ count: 1, peerName: '   ' });

    const outcome = await pairAndSync(NODE, DRIVE, AGENT);

    expect(outcome?.peerName).toBeUndefined();
    expect(readKnownPeers()[0].label).toContain('did:ad:node:');
  });

  it('reports a non-numeric count as zero rather than NaN', async () => {
    stubIrohSync({ count: 'lots' });

    expect((await pairAndSync(NODE, DRIVE, AGENT))?.count).toBe(0);
  });
});

describe('runPairing', () => {
  beforeEach(() => {
    installLocalStorage();
    vi.restoreAllMocks();
  });

  it('decodes a real pairing code and syncs it', async () => {
    stubIrohSync({ count: 3 });

    const result = await runPairing(validCode, DRIVE, AGENT);

    expect(result).toEqual({
      ok: true,
      outcome: { count: 3, peerName: undefined },
    });
  });

  it('reports an unreadable code as a value, not a throw', async () => {
    const result = await runPairing(
      'atomic://pair?v=1&node=nonsense',
      DRIVE,
      AGENT,
    );

    expect(result.ok).toBe(false);
  });

  it('explains an unsupported version rather than best-effort parsing it', async () => {
    const result = await runPairing(
      `atomic://pair?v=99&node=${NODE}&drives=*`,
      DRIVE,
      AGENT,
    );

    expect(result).toMatchObject({ ok: false });
    expect((result as { message: string }).message).toBeTruthy();
  });

  it('surfaces a sync failure as a message', async () => {
    stubIrohSync({ error: 'peer is offline' });

    expect(await runPairing(validCode, DRIVE, AGENT)).toEqual({
      ok: false,
      message: 'peer is offline',
    });
  });

  it('reports a thrown network error with a message the user can act on', async () => {
    const failing = vi.fn().mockRejectedValue(new Error('Failed to fetch'));
    globalThis.fetch = failing as unknown as typeof fetch;

    const result = await runPairing(validCode, DRIVE, AGENT);

    expect(result.ok).toBe(false);
    // The peer is recorded even though the sync failed, so retrying is a tap.
    expect(readKnownPeers()[0].nodeId).toBe(NODE);
  });
});
