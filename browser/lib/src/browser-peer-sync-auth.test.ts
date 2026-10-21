import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import { Agent } from './agent.js';
import { BrowserPeerSync } from './browser-peer-sync.js';
import { Tag } from './ws-v2.js';
import type { Store } from './store.js';

const AUTH_AGENT = 'https://atomicdata.dev/properties/auth/agent';
const BINDING = 'binding';
const CHALLENGE = `${BINDING}:${'c'.repeat(64)}`;

const sent = vi.hoisted(() => [] as Uint8Array[]);

vi.mock('./webrtc-peer.js', () => ({
  WebRtcPeer: class {
    close = vi.fn();
    // The remote's CHALLENGE is the only frame; then the channel ends.
    transport = Promise.resolve({
      send: async (frame: Uint8Array) => void sent.push(frame),
      recv: (() => {
        let served = false;

        return async () => {
          if (served) return undefined;
          served = true;

          return new Uint8Array([
            Tag.CHALLENGE,
            ...new TextEncoder().encode(CHALLENGE),
          ]);
        };
      })(),
    });
    async channelBinding() {
      return BINDING;
    }
    async createOffer() {
      return { type: 'offer', sdp: 'offer' };
    }
  },
}));

class SignalSocket extends EventTarget {
  static OPEN = 1;
  static CONNECTING = 0;
  static instances: SignalSocket[] = [];
  readyState = 1;
  constructor() {
    super();
    SignalSocket.instances.push(this);
  }
  send() {}
  close() {
    this.readyState = 3;
  }
  message(value: object) {
    this.dispatchEvent(
      new MessageEvent('message', { data: JSON.stringify(value) }),
    );
  }
}

let link: BrowserPeerSync | undefined;

beforeEach(() => {
  sent.length = 0;
  SignalSocket.instances = [];
  vi.stubGlobal('WebSocket', SignalSocket);
  vi.stubGlobal('crypto', webcrypto);
});
afterEach(() => {
  link?.close();
  vi.unstubAllGlobals();
});

/**
 * The browser-peer session (Rust `BrowserPeerSession`) pins the invite issuer
 * and checks ephemeral frames by comparing the AUTH `agent` field with the
 * canonical `atomic:agent:` subject as a string. The `did:ad:agent:` spelling
 * that goes to servers (ATOMIC-BROWSER-36) is therefore refused there with
 * "Unexpected peer identity", and no guest ever joins an unhosted drive.
 */
it('authenticates to a browser peer with the canonical agent subject', async () => {
  const agent = await Agent.generateNonExtractable();
  const db = {
    getResourceWithSnapshot: async () => ({ snapshot: undefined }),
    createPeerSession: async () => 1,
    closePeerSession: async () => {},
  };
  const store = {
    getAgent: () => agent,
    getClientDb: () => db,
  } as unknown as Store;

  link = new BrowserPeerSync(store, {
    drive: 'atomic:drive',
    room: 'a'.repeat(64),
    signalingUrl: 'ws://localhost/webrtc-signal',
  });
  // A peer id that sorts before every other id makes this side the dialer.
  (link as unknown as { peerId: string }).peerId = '0'.repeat(64);
  SignalSocket.instances[0].message({
    type: 'joined',
    peers: ['f'.repeat(64)],
  });
  await vi.waitUntil(() => sent.some(frame => frame[0] === Tag.AUTH));

  expect(agent.subject).toMatch(/^atomic:agent:/);
  const frame = sent.find(candidate => candidate[0] === Tag.AUTH)!;
  const auth = JSON.parse(new TextDecoder().decode(frame.subarray(1)));
  expect(auth[AUTH_AGENT]).toBe(agent.subject);
});
