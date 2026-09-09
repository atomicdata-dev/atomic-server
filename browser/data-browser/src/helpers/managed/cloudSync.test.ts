import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import {
  getManagedPortalUrl,
  isCloudSyncAvailable,
  enableCloudSyncForDrive,
} from './cloudSync';

// The portal URL is node-driven (or an explicit build-time override) — never
// hardcoded — so a pure self-hosted node resolves to null and the CTA hides.

/**
 * Neutralise the build-time override for the node-driven cases.
 *
 * `VITE_MANAGED_PORTAL_URL` wins over anything the node advertises, and Vite
 * loads a developer's `.env.local` in test runs too — so without this, whether
 * these pass depends on whose machine they run on. They did in fact fail for
 * exactly that reason.
 */
function withoutBuildTimeOverride() {
  beforeEach(() => {
    vi.stubEnv('VITE_MANAGED_PORTAL_URL', '');
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });
}

describe('getManagedPortalUrl', () => {
  withoutBuildTimeOverride();

  it('uses the connected node’s advertised portal', () => {
    expect(
      getManagedPortalUrl({
        managed: true,
        portalUrl: 'https://portal.example',
      }),
    ).toBe('https://portal.example');
  });

  it('is null when the node advertises no portal (pure self-hosted)', () => {
    expect(getManagedPortalUrl({ managed: false, portalUrl: null })).toBeNull();
  });

  it('is null when there is no node info at all', () => {
    expect(getManagedPortalUrl(null)).toBeNull();
    expect(getManagedPortalUrl()).toBeNull();
  });
});

describe('getManagedPortalUrl with a build-time override', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('overrides whatever the node advertises', () => {
    vi.stubEnv('VITE_MANAGED_PORTAL_URL', 'https://staging.portal.example');

    expect(
      getManagedPortalUrl({
        managed: true,
        portalUrl: 'https://portal.example',
      }),
    ).toBe('https://staging.portal.example');
  });

  it('applies even against a node that advertises nothing', () => {
    vi.stubEnv('VITE_MANAGED_PORTAL_URL', 'https://staging.portal.example');

    expect(getManagedPortalUrl({ managed: false, portalUrl: null })).toBe(
      'https://staging.portal.example',
    );
  });

  it('trims trailing slashes so callers can concatenate paths', () => {
    vi.stubEnv('VITE_MANAGED_PORTAL_URL', 'https://portal.example///');

    expect(getManagedPortalUrl(null)).toBe('https://portal.example');
  });
});

describe('isCloudSyncAvailable', () => {
  withoutBuildTimeOverride();

  it('true when a portal resolves, false otherwise', () => {
    expect(
      isCloudSyncAvailable({
        managed: true,
        portalUrl: 'https://portal.example',
      }),
    ).toBe(true);
    expect(isCloudSyncAvailable({ managed: false, portalUrl: null })).toBe(
      false,
    );
  });
});

describe('enableCloudSyncForDrive', () => {
  const realFetch = globalThis.fetch;

  // This path reports the portal it would send the user to, so it is subject to
  // the same override precedence as the getters above.
  withoutBuildTimeOverride();

  beforeEach(() => {
    globalThis.fetch = vi.fn();
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
    vi.restoreAllMocks();
  });

  it('bails to the portal (never throws) when there is no managed session', async () => {
    // GET /api/me → 401 means "no session".
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      status: 401,
      ok: false,
    } as Response);

    const setServer = vi.fn();
    const store = {
      // Should never be touched on the no-account path.
      isLocalOnlyDrive: vi.fn(() => true),
      promoteLocalDrive: vi.fn(),
      getSyncStatus: vi.fn(() => ({ serverConnected: false })),
    };

    const result = await enableCloudSyncForDrive({
      store: store as never,
      drive: 'did:ad:somedrive',
      hostingConsentAccepted: true,
      agentSubject: 'did:ad:agent:abc',
      setServer,
      managedInfo: { managed: true, portalUrl: 'https://portal.example' },
    });

    expect(result).toEqual({
      ok: false,
      reason: 'no-account',
      portalUrl: 'https://portal.example',
    });
    expect(setServer).not.toHaveBeenCalled();
    expect(store.promoteLocalDrive).not.toHaveBeenCalled();
  });
});

describe('runtime provider configuration', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('offers hosting before a colleague connects to a managed node', () => {
    vi.stubGlobal('window', {
      __ATOMIC_MANAGED__: { portalUrl: 'https://staging.portal.example/' },
    });
    expect(getManagedPortalUrl(null)).toBe('https://staging.portal.example');
    expect(isCloudSyncAvailable(null)).toBe(true);
  });
});
