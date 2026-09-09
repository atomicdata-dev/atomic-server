import { afterEach, expect, it, vi } from 'vitest';
import type { Store } from '@tomic/lib';
import { createPeerLink, parsePeerLink, savePeerLink } from './browserPeerSync';

afterEach(() => vi.unstubAllGlobals());
it('reuses the group room and lets a member issue an invitation naming themselves', () => {
  const saved = new Map<string, string>();
  vi.stubGlobal('localStorage', {
    getItem: (key: string) => saved.get(key) ?? null,
    setItem: (key: string, value: string) => saved.set(key, value),
  });
  vi.stubGlobal('window', { location: { origin: 'https://app.example' }, dispatchEvent: vi.fn() });
  const store = {
    getAgent: () => ({ subject: 'did:ad:agent:member' }),
    getServerUrl: () => 'https://signal.example',
  } as unknown as Store;
  const original = { drive: 'did:ad:drive', room: 'a'.repeat(64), signalingUrl: 'wss://signal.example/webrtc-signal', expectedPeer: 'did:ad:agent:creator' };
  savePeerLink(store, original);
  const result = createPeerLink(store, original.drive);
  expect(result.link).toEqual(original);
  expect(parsePeerLink(result.invitation)).toEqual({...original, expectedPeer:'did:ad:agent:member'});
  savePeerLink(store, result.link);
  expect(window.dispatchEvent).toHaveBeenCalledOnce();
});
