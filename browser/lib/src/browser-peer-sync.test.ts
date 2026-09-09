import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { Store } from './store.js';
import { BrowserPeerSync } from './browser-peer-sync.js';

const peers = vi.hoisted(() => [] as Array<{ close: ReturnType<typeof vi.fn>; reject: (error: Error) => void }>);
vi.mock('./webrtc-peer.js', () => ({
  WebRtcPeer: class {
    close = vi.fn();
    reject!: (error: Error) => void;
    transport = new Promise((_, reject) => { this.reject = reject; });
    constructor() { peers.push(this); }
    async createOffer() { return {type:'offer',sdp:'offer'}; }
    async acceptOffer() { return {type:'answer',sdp:'answer'}; }
    async acceptAnswer() {}
  },
}));
class SignalSocket extends EventTarget {
  static OPEN = 1;
  static instances: SignalSocket[] = [];
  readyState = 1;
  sent: Array<{type: string; to?: string}> = [];
  constructor() { super(); SignalSocket.instances.push(this); }
  send(value: string) { this.sent.push(JSON.parse(value)); }
  close() { this.readyState = 3; this.dispatchEvent(new Event('close')); }
  message(value: object) { this.dispatchEvent(new MessageEvent('message', {data:JSON.stringify(value)})); }
}
let link: BrowserPeerSync;
beforeEach(() => {
  vi.useFakeTimers();
  peers.length = 0;
  SignalSocket.instances = [];
  vi.stubGlobal('WebSocket', SignalSocket);
  vi.stubGlobal('crypto', {getRandomValues: (bytes: Uint8Array) => bytes.fill(0)});
  const agent = {subject:'did:ad:agent:me'};
  const db = {};
  const store = {getAgent:() => agent, getClientDb:() => db} as unknown as Store;
  link = new BrowserPeerSync(store,{drive:'did:ad:drive',room:'a'.repeat(64),signalingUrl:'ws://localhost/webrtc-signal'});
});
afterEach(() => { link.close(); vi.useRealTimers(); vi.unstubAllGlobals(); });
const ids = Array.from({length:7},(_,i) => String(i+1).repeat(64));

it('negotiates all seven edges without replacing earlier connections', async () => {
  const socket = SignalSocket.instances[0];
  socket.message({type:'joined', peers:ids});
  await vi.advanceTimersByTimeAsync(0);
  expect(socket.sent.filter(message => message.type === 'offer').map(message => message.to)).toEqual(ids);
  expect(peers).toHaveLength(7);
  expect(peers.every(peer => peer.close.mock.calls.length === 0)).toBe(true);
});
it('retries only the failed edge while keeping six connections alive', async () => {
  SignalSocket.instances[0].message({type:'joined',peers:ids});
  peers[0].reject(new Error('lost one channel'));
  await vi.advanceTimersByTimeAsync(3000);
  expect(peers).toHaveLength(8);
  expect(peers[0].close).toHaveBeenCalledOnce();
  expect(peers.slice(1).every(peer => peer.close.mock.calls.length === 0)).toBe(true);
});
it('removes one departing negotiation without interrupting other peers', () => {
  const socket = SignalSocket.instances[0];
  socket.message({type:'joined',peers:ids});
  socket.message({type:'left',peer:ids[2]});
  expect(peers[2].close).toHaveBeenCalledOnce();
  expect(peers.filter((_,i) => i !== 2).every(peer => peer.close.mock.calls.length === 0)).toBe(true);
});
it('ignores offers from outside the signaled membership', () => {
  SignalSocket.instances[0].message({type:'offer',from:'f'.repeat(64),sdp:'offer'});
  expect(peers).toHaveLength(0);
});
it('does not allocate an eighth remote connection', () => {
  const socket = SignalSocket.instances[0];
  socket.message({type:'joined',peers:ids});
  socket.message({type:'peer',peer:'8'.repeat(64)});
  expect(peers).toHaveLength(7);
  expect(socket.readyState).toBe(3);
});
