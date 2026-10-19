// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import {
  isLocalNetworkUrl,
  requiresLocalNetworkPermission,
} from './localNetworkAccess';

describe('isLocalNetworkUrl', () => {
  it.each([
    'http://localhost:11434',
    'http://foo.localhost',
    'http://127.0.0.1:11434',
    'http://127.5.5.5',
    'http://[::1]:11434',
    'http://10.0.0.5',
    'http://172.16.0.1',
    'http://172.31.255.1',
    'http://192.168.1.20:11434',
    'http://169.254.1.1',
    'http://mac.local:11434',
  ])('%s is local', url => {
    expect(isLocalNetworkUrl(url)).toBe(true);
  });

  it.each([
    'https://example.com',
    'http://172.32.0.1',
    'http://172.15.0.1',
    'http://11.0.0.1',
    'http://192.169.0.1',
    'https://localhost.example.com',
    'not a url',
  ])('%s is not local', url => {
    expect(isLocalNetworkUrl(url)).toBe(false);
  });
});

describe('requiresLocalNetworkPermission', () => {
  const original = window.location;

  const setHost = (hostname: string) =>
    Object.defineProperty(window, 'location', {
      value: { ...original, hostname },
      configurable: true,
    });

  afterEach(() => setHost(original.hostname));

  it('is required from a public origin', () => {
    setHost('app.atomic.place');
    expect(requiresLocalNetworkPermission('http://localhost:11434')).toBe(true);
    expect(requiresLocalNetworkPermission('https://api.example.com')).toBe(
      false,
    );
  });

  it('is not required when the page itself is local', () => {
    setHost('localhost');
    expect(requiresLocalNetworkPermission('http://localhost:11434')).toBe(
      false,
    );
  });

  it('is not required when the page itself is on [::1]', () => {
    setHost('[::1]');
    expect(requiresLocalNetworkPermission('http://localhost:11434')).toBe(
      false,
    );
  });
});
