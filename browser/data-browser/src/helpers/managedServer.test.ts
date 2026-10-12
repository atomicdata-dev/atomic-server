import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  accountCreationTarget,
  forgetServerPeer,
  fetchManagedInfo,
  isAtomicServer,
  EMPTY_NODE_INFO,
  type ManagedInfo,
} from './managedServer';

// The real one needs a keypair and WebCrypto; what matters here is that the
// exact URL being fetched is what gets signed, since the server rebuilds that
// URL to verify the signature.
vi.mock('@tomic/react', () => ({
  signRequest: vi.fn(async (url: string) => ({ 'x-atomic-signed-url': url })),
}));

describe('public node metadata', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('omits cookies belonging to a different localhost server', async () => {
    const fetcher = vi.fn(async () => new Response('{}'));
    vi.stubGlobal('fetch', fetcher);
    await fetchManagedInfo('http://localhost:9894');
    expect(fetcher).toHaveBeenCalledWith('http://localhost:9894/server', {
      headers: { Accept: 'application/ad+json' },
      credentials: 'omit',
    });
  });
});

describe('accountCreationTarget', () => {
  it("managed node with a portal URL → the portal's sign-in form", () => {
    const info: ManagedInfo = {
      managed: true,
      portalUrl: 'https://portal.example/',
    };

    // Not the root: that's the landing page, so "Create account" would drop
    // the user on a sales pitch instead of the form.
    expect(accountCreationTarget(info)).toEqual({
      kind: 'portal',
      url: 'https://portal.example/signin',
    });
  });

  it('a portal URL without a trailing slash resolves the same', () => {
    expect(
      accountCreationTarget({
        managed: true,
        portalUrl: 'https://portal.example',
      }),
    ).toEqual({ kind: 'portal', url: 'https://portal.example/signin' });
  });

  it('a portal URL with a sub-path is not appended to', () => {
    // `/signin` is absolute on the origin — a portal hosted under a path
    // would need its own handling, and silently producing
    // `…/portal/signin` here would be a guess.
    expect(
      accountCreationTarget({
        managed: true,
        portalUrl: 'https://example.com/portal/',
      }),
    ).toEqual({ kind: 'portal', url: 'https://example.com/signin' });
  });

  it('self-hosted / FOSS node → local identity (keeps the FOSS UX)', () => {
    expect(accountCreationTarget({ managed: false, portalUrl: null })).toEqual({
      kind: 'local',
    });
  });

  it('managed but without a portal URL → local (no portal to send to)', () => {
    expect(accountCreationTarget({ managed: true, portalUrl: null })).toEqual({
      kind: 'local',
    });
  });

  it('a portal URL present but not managed → local', () => {
    expect(
      accountCreationTarget({
        managed: false,
        portalUrl: 'https://portal.example/',
      }),
    ).toEqual({ kind: 'local' });
  });

  it('a self-hosted node that has an owner → no account creation', () => {
    expect(
      accountCreationTarget({
        managed: false,
        portalUrl: null,
        acceptsNewDrives: false,
      }),
    ).toEqual({ kind: 'unavailable', reason: 'node-has-owner' });
  });

  it('a node that says nothing about host mode still offers local creation', () => {
    // Every node released before host mode existed. Reading silence as "gated"
    // would remove the Create account button from all of them.
    expect(accountCreationTarget({ managed: false, portalUrl: null })).toEqual({
      kind: 'local',
    });
  });

  it('an owner-gated managed node still routes to its portal', () => {
    // Host mode gates *this disk*. Where accounts are made is the portal's
    // business, and a managed node has one.
    expect(
      accountCreationTarget({
        managed: true,
        portalUrl: 'https://portal.example/',
        acceptsNewDrives: false,
      }),
    ).toEqual({ kind: 'portal', url: 'https://portal.example/signin' });
  });
});

describe('isAtomicServer', () => {
  it('a node reporting its version is a server', () => {
    expect(
      isAtomicServer({ managed: false, portalUrl: null, version: '0.42.0' }),
    ).toBe(true);
  });

  it('a node id alone also counts (version parse could regress separately)', () => {
    expect(
      isAtomicServer({
        managed: false,
        portalUrl: null,
        nodeId: `did:ad:node:${'a'.repeat(64)}`,
      }),
    ).toBe(true);
  });

  it('an origin that never answered /server is not a server', () => {
    // What the managed deployment's shared app host produces: it serves this
    // SPA (404 or index.html at /server), which fetchManagedInfo collapses to
    // EMPTY_NODE_INFO — it must not be listed as a device.
    expect(isAtomicServer(EMPTY_NODE_INFO)).toBe(false);
  });
});

describe('forgetServerPeer', () => {
  const AGENT = { subject: 'did:ad:agent:abc' } as never;
  const NODE = `did:ad:node:${'a'.repeat(64)}`;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  function stubFetch(response: Partial<Response>) {
    const mock = vi.fn().mockResolvedValue(response as Response);
    globalThis.fetch = mock as unknown as typeof fetch;

    return mock;
  }

  it('posts the node as a query parameter, signing the exact URL', async () => {
    const fetchMock = stubFetch({ ok: true });

    await expect(
      forgetServerPeer('http://localhost:9883', NODE, AGENT),
    ).resolves.toBe(true);

    const [url, init] = fetchMock.mock.calls[0];
    // Shape asserted on the server side too, in
    // `server/tests/it/iroh_pairing.rs` — `?node=` is the contract.
    expect(url).toBe(
      `http://localhost:9883/forget-peer?node=${encodeURIComponent(NODE)}`,
    );
    expect(init.method).toBe('POST');
    // Signed over the full URL including the query string, or the server's
    // rebuild will not match.
    expect(init.headers['x-atomic-signed-url']).toBe(url);
  });

  it('reports failure rather than success when the server refuses', async () => {
    stubFetch({ ok: false, status: 401 });

    await expect(
      forgetServerPeer('http://localhost:9883', NODE, AGENT),
    ).resolves.toBe(false);
  });

  it('reports failure instead of throwing when the request cannot be made', async () => {
    globalThis.fetch = vi
      .fn()
      .mockRejectedValue(
        new Error('Failed to fetch'),
      ) as unknown as typeof fetch;

    await expect(
      forgetServerPeer('http://localhost:9883', NODE, AGENT),
    ).resolves.toBe(false);
  });

  it('does not call out at all when something required is missing', async () => {
    const fetchMock = stubFetch({ ok: true });

    await expect(forgetServerPeer('', NODE, AGENT)).resolves.toBe(false);
    await expect(
      forgetServerPeer('http://localhost:9883', '', AGENT),
    ).resolves.toBe(false);
    await expect(
      forgetServerPeer('http://localhost:9883', NODE, undefined as never),
    ).resolves.toBe(false);

    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('accountCreationTarget in a hosted distribution', () => {
  afterEach(() => vi.unstubAllEnvs());

  /**
   * The case that could not previously exist. A shipped app embeds a plain
   * atomic-server which reports `managed: false`, so inferring hosted-ness
   * from the connected node meant an app we publish could never present the
   * hosted flow it is published to present.
   */
  it('sends people to the portal even though the embedded node is not managed', () => {
    vi.stubEnv('VITE_ATOMIC_HOSTED_DISTRIBUTION', '1');
    vi.stubEnv('VITE_MANAGED_PORTAL_URL', 'https://portal.example');

    expect(accountCreationTarget({ managed: false, portalUrl: null })).toEqual({
      kind: 'portal',
      url: 'https://portal.example/signin',
    });
  });

  /** A hosted build with no portal compiled in has nowhere to send anyone. */
  it('falls back to a local identity with no portal configured', () => {
    vi.stubEnv('VITE_ATOMIC_HOSTED_DISTRIBUTION', '1');

    expect(accountCreationTarget({ managed: false, portalUrl: null })).toEqual({
      kind: 'local',
    });
  });

  /**
   * The guardrail. A source build sets neither flag and must behave exactly as
   * before — no portal, no hosted prompt, local identity.
   */
  it('leaves a FOSS build alone', () => {
    vi.stubEnv('VITE_MANAGED_PORTAL_URL', 'https://portal.example');

    expect(accountCreationTarget({ managed: false, portalUrl: null })).toEqual({
      kind: 'local',
    });
  });
});
