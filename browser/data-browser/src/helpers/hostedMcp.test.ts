import { describe, expect, it } from 'vitest';
import { isTrustedServer, safeRedirect } from './hostedMcp';

describe('isTrustedServer', () => {
  const trusted = ['https://app.example', undefined, 'did:ad:abc'];

  it('accepts the origin of a trusted node', () => {
    expect(isTrustedServer('https://app.example', trusted)).toBe(true);
    expect(isTrustedServer('https://app.example/some/path', trusted)).toBe(
      true,
    );
  });

  it('refuses another host, scheme or port', () => {
    expect(isTrustedServer('https://evil.example', trusted)).toBe(false);
    expect(isTrustedServer('http://app.example', trusted)).toBe(false);
    expect(isTrustedServer('https://app.example:8443', trusted)).toBe(false);
    expect(isTrustedServer('https://app.example.evil.example', trusted)).toBe(
      false,
    );
  });

  it('refuses empty and non-http values', () => {
    expect(isTrustedServer('', trusted)).toBe(false);
    expect(isTrustedServer('javascript:alert(1)', trusted)).toBe(false);
    expect(isTrustedServer('not a url', trusted)).toBe(false);
  });
});

describe('safeRedirect', () => {
  const uri = 'https://claude.ai/api/mcp/auth_callback';

  it('accepts the registered URI with code and state', () => {
    expect(
      safeRedirect(`${uri}?code=abc&state=xyz&iss=https%3A%2F%2Fn`, uri),
    ).toBe(`${uri}?code=abc&state=xyz&iss=https%3A%2F%2Fn`);
  });

  it('refuses script-like and foreign URLs', () => {
    expect(() => safeRedirect('javascript:alert(1)', uri)).toThrow();
    expect(() => safeRedirect('https://evil.example/cb?code=1', uri)).toThrow();
    expect(() => safeRedirect('https://claude.ai/other?code=1', uri)).toThrow();
    expect(() => safeRedirect(`${uri}?code=1&token=2`, uri)).toThrow();
    expect(() =>
      safeRedirect('https://u:p@claude.ai/api/mcp/auth_callback?code=1', uri),
    ).toThrow();
  });

  it('refuses a registered URI that could run script', () => {
    const bad = 'javascript:alert(1)';

    expect(() => safeRedirect(bad, bad)).toThrow();
    expect(() =>
      safeRedirect('http://x.example/cb?code=1', 'http://x.example/cb'),
    ).toThrow();
  });

  it('allows loopback http and a native app scheme', () => {
    expect(
      safeRedirect(
        'http://localhost:3000/cb?code=1',
        'http://localhost:3000/cb',
      ),
    ).toBe('http://localhost:3000/cb?code=1');
    expect(
      safeRedirect('cursor://mcp/callback?code=1', 'cursor://mcp/callback'),
    ).toBe('cursor://mcp/callback?code=1');
  });
});
