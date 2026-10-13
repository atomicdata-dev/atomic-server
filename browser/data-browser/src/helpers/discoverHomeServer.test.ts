import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  Agent,
  decodeB64,
  encodeGenesisCert,
  privateDriveCert,
  signGenesisCert,
  subjectForSignature,
} from '@tomic/lib';
import {
  discoverHomeServer,
  discoverHomeServerForApp,
  serverServesGenesis,
  type DiscoveryDeps,
} from './discoverHomeServer';
import { serverURLStorage } from './serverURLStorage';

const DRIVE = 'did:ad:home';

function setup(overrides: Partial<DiscoveryDeps> = {}) {
  const store = {
    getServerUrl: vi.fn(() => 'https://app.example'),
    setServerUrl: vi.fn(),
    unregisterLocalOnlyDrive: vi.fn(),
    waitForServerConnected: vi.fn(async () => true),
  };
  const persist = vi.fn();
  const deps: DiscoveryDeps = {
    wasExplicitlyChosen: () => false,
    hasEmbeddedNode: () => false,
    hasDriveData: async () => false,
    resolveOrigins: async () => ['https://a.example', 'https://b.example'],
    verifyGenesis: async () => true,
    ...overrides,
  };

  return { store, persist, deps };
}

describe('discoverHomeServer', () => {
  it('connects to the first announced origin that is a node', async () => {
    const { store, persist, deps } = setup({
      verifyGenesis: async origin => origin === 'https://b.example',
    });

    expect(await discoverHomeServer(store, DRIVE, persist, deps)).toBe(true);
    expect(store.setServerUrl).toHaveBeenCalledWith('https://b.example');
    expect(persist).toHaveBeenCalledWith('https://b.example');
    expect(store.unregisterLocalOnlyDrive).toHaveBeenCalledWith(DRIVE);
  });

  it('keeps the announced order when several answer', async () => {
    const { store, persist, deps } = setup();

    await discoverHomeServer(store, DRIVE, persist, deps);
    expect(store.setServerUrl).toHaveBeenCalledWith('https://a.example');
  });

  it('never overrides an explicitly chosen server', async () => {
    const resolveOrigins = vi.fn(async () => ['https://a.example']);
    const { store, persist, deps } = setup({
      wasExplicitlyChosen: () => true,
      resolveOrigins,
    });

    expect(await discoverHomeServer(store, DRIVE, persist, deps)).toBe(false);
    expect(resolveOrigins).not.toHaveBeenCalled();
    expect(store.setServerUrl).not.toHaveBeenCalled();
  });

  it('leaves a desktop shell with its own node alone', async () => {
    const { store, persist, deps } = setup({ hasEmbeddedNode: () => true });

    expect(await discoverHomeServer(store, DRIVE, persist, deps)).toBe(false);
    expect(store.setServerUrl).not.toHaveBeenCalled();
  });

  it('does not switch a session whose server already has the drive', async () => {
    const resolveOrigins = vi.fn(async () => ['https://a.example']);
    const { store, persist, deps } = setup({
      hasDriveData: async () => true,
      resolveOrigins,
    });

    expect(await discoverHomeServer(store, DRIVE, persist, deps)).toBe(false);
    expect(resolveOrigins).not.toHaveBeenCalled();
    expect(store.setServerUrl).not.toHaveBeenCalled();
  });

  it('stays put when no origin is announced or none verifies', async () => {
    for (const overrides of [
      { resolveOrigins: async () => [] },
      { verifyGenesis: async () => false },
    ]) {
      const { store, persist, deps } = setup(overrides);

      expect(await discoverHomeServer(store, DRIVE, persist, deps)).toBe(false);
      expect(store.setServerUrl).not.toHaveBeenCalled();
      expect(persist).not.toHaveBeenCalled();
    }
  });

  it('skips the origin it is already on', async () => {
    const verifyGenesis = vi.fn(async () => true);
    const { store, persist, deps } = setup({
      resolveOrigins: async () => ['https://app.example'],
      verifyGenesis,
    });

    expect(await discoverHomeServer(store, DRIVE, persist, deps)).toBe(false);
    expect(verifyGenesis).not.toHaveBeenCalled();
  });

  it('swallows failures', async () => {
    const { store, persist, deps } = setup({
      resolveOrigins: async () => {
        throw new Error('boom');
      },
    });

    expect(await discoverHomeServer(store, DRIVE, persist, deps)).toBe(false);
  });

  it('gives up at the deadline and does not connect late', async () => {
    vi.useFakeTimers();

    let finish: (origins: string[]) => void = () => undefined;
    const { store, persist, deps } = setup({
      resolveOrigins: () =>
        new Promise<string[]>(resolve => (finish = resolve)),
    });
    const result = discoverHomeServer(store, DRIVE, persist, deps, 1_000);

    await vi.advanceTimersByTimeAsync(1_001);
    expect(await result).toBe(false);

    finish(['https://a.example']);
    await vi.advanceTimersByTimeAsync(10);
    expect(store.setServerUrl).not.toHaveBeenCalled();
    vi.useRealTimers();
  });

  it('does not connect when the person picked a server while it was asking', async () => {
    let chosen = false;
    const { store, persist, deps } = setup({
      wasExplicitlyChosen: () => chosen,
      verifyGenesis: async () => {
        chosen = true;

        return true;
      },
    });

    expect(await discoverHomeServer(store, DRIVE, persist, deps)).toBe(false);
    expect(store.setServerUrl).not.toHaveBeenCalled();
  });

  it('skips a node that does not serve the drive', async () => {
    const { store, persist, deps } = setup({
      verifyGenesis: async origin => origin === 'https://b.example',
    });

    expect(await discoverHomeServer(store, DRIVE, persist, deps)).toBe(true);
    expect(store.setServerUrl).toHaveBeenCalledWith('https://b.example');
  });

  it('stays put when no node verifies', async () => {
    const { store, persist, deps } = setup({
      verifyGenesis: async () => false,
    });

    expect(await discoverHomeServer(store, DRIVE, persist, deps)).toBe(false);
    expect(store.setServerUrl).not.toHaveBeenCalled();
  });

  it('checks each candidate once and at most three', async () => {
    const verifyGenesis = vi.fn(async (_origin: string) => false);
    const { store, persist, deps } = setup({
      resolveOrigins: async () => [
        'https://a.example',
        'https://a.example',
        'https://b.example',
        'https://c.example',
        'https://d.example',
        'https://e.example',
      ],
      verifyGenesis,
    });

    await discoverHomeServer(store, DRIVE, persist, deps);
    expect(verifyGenesis.mock.calls.map(c => c[0])).toEqual([
      'https://a.example',
      'https://b.example',
      'https://c.example',
    ]);
  });
});

describe('discoverHomeServerForApp', () => {
  // Node environment (noble rejects jsdom's Uint8Array realm): a plain map
  // stands in for localStorage.
  beforeEach(() => {
    const data = new Map<string, string>();

    vi.stubGlobal('localStorage', {
      getItem: (k: string) => data.get(k) ?? null,
      setItem: (k: string, v: string) => void data.set(k, v),
      removeItem: (k: string) => void data.delete(k),
    });
  });
  afterEach(() => vi.unstubAllGlobals());

  it('remembers the server as inferred, not explicit', async () => {
    const setBaseURL = vi.fn();
    const store = {
      getServerUrl: () => 'https://app.example',
      setServerUrl: vi.fn(),
      unregisterLocalOnlyDrive: vi.fn(),
      waitForServerConnected: vi.fn(async () => true),
    };

    // A previous explicit choice must not keep vouching for the new server.
    serverURLStorage.set('https://chosen.example', true);
    expect(serverURLStorage.wasExplicitlyChosen()).toBe(true);

    const found = await discoverHomeServerForApp(
      store,
      DRIVE,
      setBaseURL,
      async () => false,
      {
        wasExplicitlyChosen: () => false,
        hasEmbeddedNode: () => false,
        resolveOrigins: async () => ['https://a.example'],
        verifyGenesis: async () => true,
      },
    );

    expect(found).toBe(true);
    expect(setBaseURL).toHaveBeenCalledWith('https://a.example');
    expect(serverURLStorage.get()).toBe('https://a.example');
    expect(serverURLStorage.wasExplicitlyChosen()).toBe(false);
  });
});

describe('serverServesGenesis', () => {
  const GENESIS = 'https://atomicdata.dev/properties/genesis';

  async function drive() {
    const keys = await Agent.generateKeyPair();
    const cert = privateDriveCert(new Uint8Array(decodeB64(keys.publicKey)));
    const signature = await signGenesisCert(
      cert,
      new Uint8Array(decodeB64(keys.privateKey)),
    );

    return {
      did: subjectForSignature(signature),
      genesis: btoa(String.fromCharCode(...encodeGenesisCert(cert)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, ''),
    };
  }

  function serve(body: unknown, init: ResponseInit = { status: 200 }) {
    const fetchMock = vi.fn(
      async (_url: string, _init?: RequestInit) =>
        new Response(JSON.stringify(body), init),
    );

    vi.stubGlobal('fetch', fetchMock);

    return fetchMock;
  }

  afterEach(() => vi.unstubAllGlobals());

  it('accepts the genesis that signs to the DID, fetched without redirects', async () => {
    const home = await drive();
    const fetchMock = serve({ [GENESIS]: home.genesis });

    expect(await serverServesGenesis('https://a.example', home.did)).toBe(true);
    expect(fetchMock.mock.calls[0][0]).toBe(
      `https://a.example/genesis?subject=${encodeURIComponent(home.did)}`,
    );
    expect(fetchMock.mock.calls[0][1]).toMatchObject({
      redirect: 'error',
      credentials: 'omit',
    });
  });

  it('rejects a genesis forged for another DID', async () => {
    const home = await drive();
    const attacker = await drive();

    serve({ [GENESIS]: attacker.genesis });
    expect(await serverServesGenesis('https://evil.example', home.did)).toBe(
      false,
    );
  });

  it('rejects a missing, garbled or refused answer', async () => {
    const home = await drive();

    serve({ other: 'x' });
    expect(await serverServesGenesis('https://a.example', home.did)).toBe(
      false,
    );
    serve({ [GENESIS]: 'AAAA' });
    expect(await serverServesGenesis('https://a.example', home.did)).toBe(
      false,
    );
    serve({}, { status: 401 });
    expect(await serverServesGenesis('https://a.example', home.did)).toBe(
      false,
    );
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(new TypeError('redirect')),
    );
    expect(await serverServesGenesis('https://a.example', home.did)).toBe(
      false,
    );
  });
});
