import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { Store } from './store.js';
import { webcrypto } from 'node:crypto';
import { BrowserPeerSync, browserPeerId } from './browser-peer-sync.js';

const peers = vi.hoisted(
  () =>
    [] as Array<{
      close: ReturnType<typeof vi.fn>;
      reject: (error: Error) => void;
    }>,
);
vi.mock('./webrtc-peer.js', () => ({
  WebRtcPeer: class {
    close = vi.fn();
    reject!: (error: Error) => void;
    transport = new Promise((_, reject) => {
      this.reject = reject;
    });
    constructor() {
      peers.push(this);
    }
    async createOffer() {
      return { type: 'offer', sdp: 'offer' };
    }
    async acceptOffer() {
      return { type: 'answer', sdp: 'answer' };
    }
    async acceptAnswer() {}
  },
}));
class SignalSocket extends EventTarget {
  static OPEN = 1;
  static CONNECTING = 0;
  static instances: SignalSocket[] = [];
  readyState = 1;
  sent: Array<{ type: string; to?: string }> = [];
  constructor() {
    super();
    SignalSocket.instances.push(this);
  }
  send(value: string) {
    this.sent.push(JSON.parse(value));
  }
  close() {
    this.readyState = 3;
    this.dispatchEvent(new Event('close'));
  }
  message(value: object) {
    this.dispatchEvent(
      new MessageEvent('message', { data: JSON.stringify(value) }),
    );
  }
}
let link: BrowserPeerSync;
beforeEach(() => {
  vi.useFakeTimers();
  peers.length = 0;
  SignalSocket.instances = [];
  vi.stubGlobal('WebSocket', SignalSocket);
  vi.stubGlobal('crypto', {
    getRandomValues: (bytes: Uint8Array) => bytes.fill(0),
  });
  const agent = { subject: 'did:ad:agent:me' };
  const db = {};
  const store = {
    getAgent: () => agent,
    getClientDb: () => db,
  } as unknown as Store;
  link = new BrowserPeerSync(store, {
    drive: 'did:ad:drive',
    room: 'a'.repeat(64),
    signalingUrl: 'ws://localhost/webrtc-signal',
  });
});
afterEach(() => {
  link.close();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});
const ids = Array.from({ length: 7 }, (_, i) => String(i + 1).repeat(64));

it('negotiates all seven edges without replacing earlier connections', async () => {
  const socket = SignalSocket.instances[0];
  socket.message({ type: 'joined', peers: ids });
  await vi.advanceTimersByTimeAsync(0);
  expect(
    socket.sent
      .filter(message => message.type === 'offer')
      .map(message => message.to),
  ).toEqual(ids);
  expect(peers).toHaveLength(7);
  expect(peers.every(peer => peer.close.mock.calls.length === 0)).toBe(true);
});
it('retries only the failed edge while keeping six connections alive', async () => {
  SignalSocket.instances[0].message({ type: 'joined', peers: ids });
  peers[0].reject(new Error('lost one channel'));
  await vi.advanceTimersByTimeAsync(3000);
  expect(peers).toHaveLength(8);
  expect(peers[0].close).toHaveBeenCalledOnce();
  expect(peers.slice(1).every(peer => peer.close.mock.calls.length === 0)).toBe(
    true,
  );
});
it('backs off repeated failures and does not redial early on discovery refresh', async () => {
  const socket = SignalSocket.instances[0];
  socket.message({ type: 'joined', peers: [ids[0]] });
  peers[0].reject(new Error('ICE failed'));
  await vi.advanceTimersByTimeAsync(3000);
  expect(peers).toHaveLength(2);
  peers[1].reject(new Error('ICE failed'));
  await vi.advanceTimersByTimeAsync(0);
  socket.message({ type: 'peer', peer: ids[0] });
  expect(peers).toHaveLength(2);
  await vi.advanceTimersByTimeAsync(5999);
  expect(peers).toHaveLength(2);
  await vi.advanceTimersByTimeAsync(1);
  expect(peers).toHaveLength(3);
});

function markReady(sync: BrowserPeerSync, id: string) {
  const connections = (sync as unknown as { connections: Map<string, object> })
    .connections;
  (connections.get(id) as unknown as { onReady(path: string): void }).onReady(
    'direct',
  );
}

it('keeps backing off when connections die soon after becoming ready', async () => {
  const socket = SignalSocket.instances[0];
  socket.message({ type: 'joined', peers: [ids[0]] });
  let count = 1;

  for (const delay of [3000, 6000, 12000]) {
    markReady(link, ids[0]);
    await vi.advanceTimersByTimeAsync(5000);
    peers[count - 1].reject(new Error('Peer access removed'));
    await vi.advanceTimersByTimeAsync(delay - 1);
    expect(peers).toHaveLength(count);
    await vi.advanceTimersByTimeAsync(1);
    expect(peers).toHaveLength(++count);
  }
  // A connection that stays up for the stable period resets the backoff.

  markReady(link, ids[0]);
  await vi.advanceTimersByTimeAsync(30_000);
  peers[count - 1].reject(new Error('remote closed'));
  await vi.advanceTimersByTimeAsync(2999);
  expect(peers).toHaveLength(count);
  await vi.advanceTimersByTimeAsync(1);
  expect(peers).toHaveLength(count + 1);
});
it('removes one departing negotiation without interrupting other peers', () => {
  const socket = SignalSocket.instances[0];
  socket.message({ type: 'joined', peers: ids });
  socket.message({ type: 'left', peer: ids[2] });
  expect(peers[2].close).toHaveBeenCalledOnce();
  expect(
    peers
      .filter((_, i) => i !== 2)
      .every(peer => peer.close.mock.calls.length === 0),
  ).toBe(true);
});
it('ignores offers from outside the signaled membership', () => {
  SignalSocket.instances[0].message({
    type: 'offer',
    from: 'f'.repeat(64),
    sdp: 'offer',
  });
  expect(peers).toHaveLength(0);
});
it('does not allocate an eighth remote connection', () => {
  const socket = SignalSocket.instances[0];
  socket.message({ type: 'joined', peers: ids });
  socket.message({ type: 'peer', peer: '8'.repeat(64) });
  expect(peers).toHaveLength(7);
  expect(socket.readyState).toBe(3);
});

it('stops a connecting socket without joining or reconnecting after it opens', async () => {
  const socket = SignalSocket.instances[0];
  socket.readyState = SignalSocket.CONNECTING;
  const close = vi.spyOn(socket, 'close');
  link.close();
  expect(close).not.toHaveBeenCalled();
  socket.readyState = SignalSocket.OPEN;
  socket.dispatchEvent(new Event('open'));
  expect(close).toHaveBeenCalledOnce();
  expect(socket.sent).toEqual([]);
  await vi.advanceTimersByTimeAsync(6000);
  expect(SignalSocket.instances).toHaveLength(1);
});

function memoryStorage() {
  const items = new Map<string, string>();

  return {
    getItem: (key: string) => items.get(key) ?? null,
    setItem: (key: string, value: string) => void items.set(key, value),
  };
}

it('gives every tab of one browser the same prefix per agent and room', async () => {
  vi.stubGlobal('crypto', webcrypto);
  vi.stubGlobal('localStorage', memoryStorage());
  const room = 'a'.repeat(64);
  const one = await browserPeerId('did:ad:agent:me', room);
  const two = await browserPeerId('did:ad:agent:me', room);
  expect(one).toMatch(/^[a-f0-9]{64}$/);
  expect(one).not.toBe(two);
  expect(one.slice(0, 16)).toBe(two.slice(0, 16));
  const elsewhere = await browserPeerId('did:ad:agent:me', 'b'.repeat(64));
  expect(elsewhere.slice(0, 16)).not.toBe(one.slice(0, 16));
});

it('does not pair with another tab of the same browser', async () => {
  vi.stubGlobal('crypto', webcrypto);
  vi.stubGlobal('localStorage', memoryStorage());
  const socket = SignalSocket.instances[0];
  socket.dispatchEvent(new Event('open'));
  await vi.waitUntil(() =>
    socket.sent.some(message => message.type === 'join'),
  );
  const join = socket.sent.find(message => message.type === 'join') as {
    peer: string;
  };
  expect(join.peer).toMatch(/^[a-f0-9]{64}$/);
  const ownTab = join.peer.slice(0, 16) + 'f'.repeat(48);
  const otherBrowser = 'f'.repeat(64);
  socket.message({ type: 'joined', peers: [ownTab, otherBrowser] });
  await vi.advanceTimersByTimeAsync(0);
  expect(
    socket.sent
      .filter(message => message.type === 'offer')
      .map(message => message.to),
  ).toEqual([otherBrowser]);
});

function linkWithStatus(statuses: string[]) {
  const agent = { subject: 'did:ad:agent:me' };
  const db = {};
  const store = {
    getAgent: () => agent,
    getClientDb: () => db,
  } as unknown as Store;

  return new BrowserPeerSync(store, {
    drive: 'did:ad:drive',
    room: 'a'.repeat(64),
    signalingUrl: 'ws://localhost/webrtc-signal',
    onStatus: status => statuses.push(status),
  });
}

it('counts distinct remote browsers, not their tabs', () => {
  const statuses: string[] = [];
  const counted = linkWithStatus(statuses);
  const socket = SignalSocket.instances.at(-1)!;
  const tab = (prefix: string, n: string) => prefix.repeat(16) + n.repeat(48);
  const peerIds = [tab('1', '1'), tab('1', '2'), tab('2', '3')];
  socket.message({ type: 'joined', peers: peerIds });

  for (const id of peerIds) markReady(counted, id);
  expect(statuses.at(-1)).toBe('Connected to 2 browsers');
  counted.close();
});

it('keeps the last failure in the waiting status', async () => {
  const statuses: string[] = [];
  const failing = linkWithStatus(statuses);
  SignalSocket.instances.at(-1)!.message({ type: 'joined', peers: [ids[0]] });
  peers.at(-1)!.reject(new Error('no route'));
  await vi.advanceTimersByTimeAsync(0);
  expect(statuses.at(-1)).toBe('no route');
  (failing as unknown as { status(): void }).status();
  expect(statuses.at(-1)).toBe(
    'Waiting for a peer (last attempt failed: no route)',
  );
  await vi.advanceTimersByTimeAsync(3000);
  markReady(failing, ids[0]);
  expect(statuses.at(-1)).toBe('Connected to 1 browser');
  failing.close();
});
