import { afterEach, expect, it, vi } from 'vitest';
import { BrowserPeerSync, server, type Store } from '@tomic/lib';
vi.mock('@tomic/lib', async importOriginal => ({
  ...(await importOriginal<typeof import('@tomic/lib')>()),
  BrowserPeerSync: vi.fn(
    class {
      close() {}
    },
  ),
}));
import {
  createPeerLink,
  parsePeerLink,
  savePeerLink,
  defaultPeerSignalingUrl,
} from './browserPeerSync';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});
it('reuses the group room and lets a member issue an invitation naming themselves', () => {
  const saved = new Map<string, string>();
  vi.stubGlobal('localStorage', {
    getItem: (key: string) => saved.get(key) ?? null,
    setItem: (key: string, value: string) => saved.set(key, value),
  });
  vi.stubGlobal('window', {
    location: { origin: 'https://app.example' },
    dispatchEvent: vi.fn(),
  });
  const store = {
    getAgent: () => ({ subject: 'did:ad:agent:member' }),
    getServerUrl: () => 'https://signal.example',
  } as unknown as Store;
  const original = {
    drive: 'did:ad:drive',
    room: 'a'.repeat(64),
    signalingUrl: 'wss://signal.example/webrtc-signal',
    expectedPeer: 'did:ad:agent:creator',
  };
  savePeerLink(store, original);
  const result = createPeerLink(store, original.drive);
  expect(result.link).toEqual(original);
  expect(parsePeerLink(result.invitation)).toEqual({
    ...original,
    expectedPeer: 'did:ad:agent:member',
  });
  savePeerLink(store, result.link);
  expect(window.dispatchEvent).toHaveBeenCalledOnce();
});

it('discovers through SaaS without consulting a data server or account', () => {
  vi.stubEnv('VITE_ATOMIC_SIGNALING_URL', '');
  vi.stubEnv('VITE_MANAGED_PORTAL_URL', '');
  vi.stubGlobal('window', { location: { hostname: 'localhost' } });
  expect(defaultPeerSignalingUrl()).toBe('wss://atomicserver.eu/webrtc-signal');
  vi.stubGlobal('window', {
    location: { hostname: 'app.staging.atomicserver.eu' },
  });
  expect(defaultPeerSignalingUrl()).toBe(
    'wss://staging.atomicserver.eu/webrtc-signal',
  );
});
it('uses the configured SaaS deployment and supports explicit signaling overrides', () => {
  vi.stubEnv('VITE_ATOMIC_SIGNALING_URL', '');
  vi.stubEnv('VITE_MANAGED_PORTAL_URL', 'http://localhost:49237');
  expect(defaultPeerSignalingUrl()).toBe('ws://localhost:49237/webrtc-signal');
  vi.stubEnv('VITE_ATOMIC_SIGNALING_URL', 'wss://community.example/signal');
  expect(defaultPeerSignalingUrl()).toBe('wss://community.example/signal');
});
it('creates a local-drive invitation without asking a node for discovery', () => {
  vi.stubEnv('VITE_ATOMIC_SIGNALING_URL', '');
  vi.stubEnv('VITE_MANAGED_PORTAL_URL', 'https://staging.atomicserver.eu');
  vi.stubGlobal('localStorage', { getItem: () => null });
  vi.stubGlobal('window', { location: { origin: 'http://localhost:6747' } });
  const store = {
    getAgent: () => ({ subject: 'did:ad:agent:local' }),
    getServerUrl: () => {
      throw new Error('No data node exists');
    },
  } as unknown as Store;
  const { invitation } = createPeerLink(store, 'did:ad:local-drive');
  expect(parsePeerLink(invitation).signalingUrl).toBe(
    'wss://staging.atomicserver.eu/webrtc-signal',
  );
});

it('derives the same discovery room independently, and separates drives', async () => {
  const { automaticPeerRoom } = await import('./browserPeerSync');
  expect(await automaticPeerRoom('did:ad:one')).toMatch(/^[a-f0-9]{64}$/);
  expect(await automaticPeerRoom('did:ad:one')).toBe(
    await automaticPeerRoom('did:ad:one'),
  );
  expect(await automaticPeerRoom('did:ad:one')).not.toBe(
    await automaticPeerRoom('did:ad:two'),
  );
});

it('automatically connects stored drives once, without bootstrapping unknown drives', async () => {
  const { discoverPeerDrives, stopPeerLinks } =
    await import('./browserPeerSync');
  vi.stubGlobal('window', {
    location: { hostname: 'localhost' },
    dispatchEvent: vi.fn(),
  });
  const agent = { subject: 'did:ad:agent:test' };
  const db = {
    getResourceWithSnapshot: vi.fn(async (drive: string) => ({
      snapshot: drive === 'did:ad:stored' ? 'snapshot' : undefined,
    })),
  };
  const resources = new Map(
    ['did:ad:stored', 'did:ad:unknown'].map(subject => [
      subject,
      {
        subject,
        isReady: () => true,
        hasClasses: (cls: string) => cls === server.classes.drive,
      },
    ]),
  );
  const store = {
    getAgent: () => agent,
    getClientDb: () => db,
    resources,
  } as unknown as Store;
  vi.mocked(BrowserPeerSync).mockImplementation(function () {
    return { close: vi.fn() } as unknown as BrowserPeerSync;
  });
  vi.mocked(BrowserPeerSync).mockClear();
  await discoverPeerDrives(store);
  await discoverPeerDrives(store);
  expect(BrowserPeerSync).toHaveBeenCalledOnce();
  expect(BrowserPeerSync).toHaveBeenCalledWith(
    store,
    expect.objectContaining({ drive: 'did:ad:stored' }),
  );
  stopPeerLinks(store);
});
