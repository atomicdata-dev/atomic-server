import { expect, it } from 'vitest';
import { WebRtcTransport } from './webrtc-transport.js';
class Channel extends EventTarget {
  ordered = true;
  maxRetransmits = null;
  maxPacketLifeTime = null;
  binaryType = 'arraybuffer';
  bufferedAmount = 0;
  bufferedAmountLowThreshold = 0;
  readyState = 'open';
  sent: ArrayBuffer[] = [];
  peer?: Channel;
  send(data: ArrayBuffer) {
    this.sent.push(data);
    this.peer?.dispatchEvent(new MessageEvent('message', { data }));
  }
  close() {
    this.readyState = 'closed';
    this.dispatchEvent(new Event('close'));
  }
}

function pair() {
  const a = new Channel();
  const b = new Channel();
  a.peer = b;
  b.peer = a;

  return {
    a,
    b,
    sender: new WebRtcTransport(a as unknown as RTCDataChannel, () => 16),
    receiver: new WebRtcTransport(b as unknown as RTCDataChannel),
  };
}

it('reassembles fragmented frames and serializes concurrent sends', async () => {
  const { a, sender, receiver } = pair();
  const large = Uint8Array.from({ length: 1000 }, (_, i) => i % 256);
  await Promise.all([
    sender.send(large),
    sender.send(new Uint8Array([19, 42])),
  ]);
  expect(await receiver.recv()).toEqual(large);
  expect(await receiver.recv()).toEqual(new Uint8Array([19, 42]));
  expect(a.sent.every(frame => frame.byteLength <= 16)).toBe(true);
});
it('snapshots caller buffers', async () => {
  const { sender, receiver } = pair();
  const frame = new Uint8Array([1]);
  const sent = sender.send(frame);
  frame.fill(9);
  await sent;
  expect(await receiver.recv()).toEqual(new Uint8Array([1]));
});
it('cancels a backpressured write on close', async () => {
  const { a, sender } = pair();
  a.bufferedAmount = 200_000;
  const rejected = expect(sender.send(new Uint8Array([1]))).rejects.toThrow(
    'closed',
  );
  await Promise.resolve();
  expect(a.sent).toHaveLength(0);
  sender.close();
  await rejected;
});
it('resumes when the buffer drains', async () => {
  const { a, sender, receiver } = pair();
  a.bufferedAmount = 200_000;
  const sent = sender.send(new Uint8Array([1]));
  await Promise.resolve();
  a.bufferedAmount = 0;
  a.dispatchEvent(new Event('bufferedamountlow'));
  await sent;
  expect(await receiver.recv()).toEqual(new Uint8Array([1]));
});
it('rejects oversized frames before allocating the payload', async () => {
  const { b, receiver } = pair();
  const data = new ArrayBuffer(4);
  new DataView(data).setUint32(0, 0xffffffff);
  b.dispatchEvent(new MessageEvent('message', { data }));
  await expect(receiver.recv()).rejects.toThrow('size');
  expect(b.readyState).toBe('closed');
});
it('rejects truncated frames and resolves clean EOF', async () => {
  const { b, receiver } = pair();
  const data = new ArrayBuffer(4);
  new DataView(data).setUint32(0, 20);
  b.dispatchEvent(new MessageEvent('message', { data }));
  b.close();
  await expect(receiver.recv()).rejects.toThrow('Truncated');
  const clean = pair();
  const pending = clean.receiver.recv();
  clean.receiver.close();
  expect(await pending).toBeNull();
});
it('refuses unreliable channels', () => {
  const a = new Channel();
  a.ordered = false;
  expect(() => new WebRtcTransport(a as unknown as RTCDataChannel)).toThrow(
    'reliable',
  );
});

it('bounds queued outbound frames while backpressured', async () => {
  const channel = new Channel();
  channel.bufferedAmount = 200_000;
  const pipe = new WebRtcTransport(
    channel as unknown as RTCDataChannel,
    () => 16,
    4,
  );
  const pending = pipe.send(new Uint8Array([1, 2, 3]));
  const rejected = expect(pending).rejects.toThrow('closed');
  await expect(pipe.send(new Uint8Array([4, 5]))).rejects.toThrow('queue full');
  pipe.close();
  await rejected;
});

it('bounds the receive queue and rejects frame overflow', async () => {
  const channel = new Channel();
  const pipe = new WebRtcTransport(
    channel as unknown as RTCDataChannel,
    () => 16,
    4,
  );

  const send = (length: number, payload: number[]) => {
    const bytes = new Uint8Array(4 + payload.length);
    new DataView(bytes.buffer).setUint32(0, length);
    bytes.set(payload, 4);
    channel.dispatchEvent(new MessageEvent('message', { data: bytes.buffer }));
  };

  send(3, [1, 2, 3]);
  send(3, [4, 5, 6]);
  await expect(pipe.recv()).rejects.toThrow('queue full');
  const other = pair();
  const bytes = new Uint8Array([0, 0, 0, 1, 2, 3]);
  other.b.dispatchEvent(new MessageEvent('message', { data: bytes.buffer }));
  await expect(other.receiver.recv()).rejects.toThrow('overflow');
});
