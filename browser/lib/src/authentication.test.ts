import { afterEach, describe, it, expect, vi } from 'vitest';
import type { Agent } from './agent.js';
import {
  AUTH_PROOF_MAX_AGE_MS,
  AUTH_PROOF_REFRESH_MS,
  checkAuthenticationCookie,
  parentDomainsOf,
  setCookieAuthentication,
} from './authentication.js';

describe('parentDomainsOf', () => {
  it('lists the host and every parent, excluding the TLD', () => {
    // The host itself is included on purpose: `Domain=atomicdata.dev` is a
    // different cookie entry from the host-only one, and on the apex host it
    // is the entry that leaks down into subdomains.
    // The TLD is excluded because browsers reject `Domain=dev` outright.
    expect(parentDomainsOf('staging.atomicdata.dev')).toEqual([
      'staging.atomicdata.dev',
      'atomicdata.dev',
    ]);
  });

  it('includes the apex itself, so production can clear its own wide cookie', () => {
    expect(parentDomainsOf('atomicdata.dev')).toContain('atomicdata.dev');
  });

  it('handles a bare apex domain', () => {
    expect(parentDomainsOf('atomicdata.dev')).toEqual(['atomicdata.dev']);
  });

  it('walks several levels of subdomain', () => {
    expect(parentDomainsOf('a.b.example.com')).toEqual([
      'a.b.example.com',
      'b.example.com',
      'example.com',
    ]);
  });

  it('does not produce a bare TLD to clear', () => {
    // `Domain=dev` would be rejected by the browser, and naming it would be a
    // request to clear a cookie for every .dev site.
    for (const host of ['atomicdata.dev', 'staging.atomicdata.dev']) {
      expect(parentDomainsOf(host)).not.toContain('dev');
    }
  });

  it('leaves localhost alone', () => {
    // Nothing to widen to, so nothing to clear beyond the host itself.
    expect(parentDomainsOf('localhost')).toEqual([]);
  });
});

/**
 * The staging 401 flood: 4,215 requests in one group, every one carrying the
 * same `signed at` timestamp while the server's clock advanced past the five
 * minutes it accepts. The cookie was installed once and lived for a day, and
 * nothing ever asked how old the proof inside it was.
 */
describe('checkAuthenticationCookie', () => {
  const AUTH_TIMESTAMP = 'https://atomicdata.dev/properties/auth/timestamp';

  const proofCookie = (signedAt: number) =>
    `atomic_session=${encodeURIComponent(
      btoa(JSON.stringify({ [AUTH_TIMESTAMP]: signedAt })),
    )}`;

  const withCookie = (cookie: string) => {
    vi.stubGlobal('document', { cookie });
  };

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('is false when there is no cookie at all', () => {
    withCookie('');
    expect(checkAuthenticationCookie()).toBe(false);
  });

  it('accepts a proof that was just signed', () => {
    withCookie(proofCookie(Date.now()));
    expect(checkAuthenticationCookie()).toBe(true);
  });

  it('reports an ageing proof as absent, so a fresh one gets installed', () => {
    // Still inside the server's five minutes, but close enough that the next
    // request should carry a new proof rather than this one.
    withCookie(proofCookie(Date.now() - AUTH_PROOF_REFRESH_MS - 1));
    expect(checkAuthenticationCookie()).toBe(false);
  });

  it('reports the proof staging kept re-sending as absent', () => {
    // 515,692 ms old, the exact age in the flood's own error message.
    withCookie(proofCookie(Date.now() - 515_692));
    expect(checkAuthenticationCookie()).toBe(false);
  });

  it('finds the cookie among others', () => {
    withCookie(`_ga=GA1.1.147665899.1676287441; ${proofCookie(Date.now())}`);
    expect(checkAuthenticationCookie()).toBe(true);
  });

  it('rejects a cookie it cannot read the age of', () => {
    // An older build's cookie, or a truncated one. Presenting it is exactly
    // what this check exists to stop.
    withCookie('atomic_session=not-base64-json');
    expect(checkAuthenticationCookie()).toBe(false);
  });

  it('is not confused by a cookie whose name merely ends in the same word', () => {
    withCookie(`other_atomic_session=${proofCookie(Date.now()).slice(15)}`);
    expect(checkAuthenticationCookie()).toBe(false);
  });
});

describe('setCookieAuthentication', () => {
  const agent = {
    subject: 'https://example.com/agents/tester',
    getPublicKey: async () => 'cHVibGljLWtleQ==',
    createSignature: async () => 'c2lnbmF0dXJl',
  } as unknown as Agent;

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('writes a cookie that dies with the proof inside it', async () => {
    const written: string[] = [];
    vi.stubGlobal('document', {
      get cookie() {
        return written.at(-1) ?? '';
      },
      set cookie(value: string) {
        written.push(value);
      },
    });
    vi.stubGlobal('location', { hostname: 'example.com' });

    const before = Date.now();
    await setCookieAuthentication('https://example.com', agent);
    const after = Date.now();

    // Skipping the `Max-Age=-…` writes, which delete the over-broad cookies
    // an older build left behind rather than install this one.
    const session = written.find(
      c => c.startsWith('atomic_session=') && !c.includes('Max-Age=-'),
    );
    expect(session).toBeDefined();

    const expires = session!.match(/Expires=([^;]+)/)?.[1];
    expect(expires).toBeDefined();

    // It used to be a day, which is what let a five-minute proof be presented
    // for hours.
    // The cookie is stamped somewhere between `before` and `after`, so
    // compare against `after`: with `before` the signing time alone can push
    // the lifetime over the maximum.
    const expiresAt = Date.parse(expires!);
    expect(expiresAt).toBeGreaterThan(before);
    expect(expiresAt).toBeLessThanOrEqual(after + AUTH_PROOF_MAX_AGE_MS);
  });

  it('installs a proof the freshness check immediately accepts', async () => {
    let cookie = '';
    vi.stubGlobal('document', {
      get cookie() {
        return cookie;
      },
      set cookie(value: string) {
        if (value.startsWith('atomic_session=') && !value.includes('Max-Age=-'))
          cookie = value.split(';')[0];
      },
    });
    vi.stubGlobal('location', { hostname: 'example.com' });

    await setCookieAuthentication('https://example.com', agent);
    expect(checkAuthenticationCookie()).toBe(true);
  });
});
