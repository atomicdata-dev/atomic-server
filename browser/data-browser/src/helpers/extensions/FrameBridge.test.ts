import { expect, it, vi } from 'vitest';
import { FrameBridge, type FrameSession } from './FrameBridge';

function fixture() {
  let message: (event: MessageEvent) => void = () => {};
  let reload: () => void = () => {};
  const target = { postMessage: vi.fn() };
  const host = {
    addEventListener: (_: string, listener: unknown) => {
      message = listener as typeof message;
    },
    removeEventListener: vi.fn(),
  };
  const frame = {
    contentWindow: target,
    addEventListener: (_: string, listener: unknown) => {
      reload = listener as typeof reload;
    },
    removeEventListener: vi.fn(),
  };
  const received: FrameSession[] = [];
  const bridge = new FrameBridge(
    frame as never,
    (_, session) => {
      received.push(session);
    },
    'dark',
    host as never,
  );
  const send = (data: unknown, source: unknown = target) =>
    message({ data, source } as MessageEvent);

  return {
    bridge,
    send,
    received,
    target,
    reload: () => reload(),
    host,
    frame,
  };
}

it('accepts both adapter envelopes only from its own frame, including ready messages', () => {
  const f = fixture();
  f.send({ type: '__atomic_plugin_ready' }, {});
  f.send({ __atomic: true, id: 1, op: 'get' }, {});
  f.send(null);
  expect(f.target.postMessage).not.toHaveBeenCalled();
  expect(f.received).toHaveLength(0);
  f.send({ type: '__atomic_plugin_ready' });
  expect(f.target.postMessage).toHaveBeenLastCalledWith(
    { type: '__atomic_style', css: 'dark' },
    '*',
  );
  f.send({ __atomic: true, id: 1, op: 'get' });
  f.send({ type: 'get-resource', requestId: 'legacy' });
  expect(f.received).toHaveLength(2);
  f.bridge.setStyle('light');
  expect(f.target.postMessage).toHaveBeenLastCalledWith(
    { type: '__atomic_style', css: 'light' },
    '*',
  );
});

it('deduplicates subscriptions and releases them on unsubscribe, reload and close', () => {
  const f = fixture();
  f.send({ id: 1 });
  const stop = vi.fn();
  const subscribe = vi.fn(() => stop);
  f.received[0].watch('row', subscribe);
  f.received[0].watch('row', subscribe);
  expect(subscribe).toHaveBeenCalledTimes(1);
  // Initial document load may follow its ready message and first requests.
  f.reload();
  expect(stop).not.toHaveBeenCalled();
  f.received[0].unwatch('row');
  expect(stop).toHaveBeenCalledTimes(1);
  f.received[0].watch('row', subscribe);
  f.send({ type: '__atomic_plugin_ready' });
  expect(stop).toHaveBeenCalledTimes(2);
  f.received[0].watch('late', subscribe);
  f.received[0].post('late response');
  expect(subscribe).toHaveBeenCalledTimes(2);
  expect(f.target.postMessage).not.toHaveBeenCalledWith('late response', '*');
  f.send({ id: 2 });
  f.received[1].watch('row', subscribe);
  f.bridge.close();
  f.bridge.close();
  f.received[1].post('after unmount');
  expect(stop).toHaveBeenCalledTimes(3);
  expect(f.target.postMessage).not.toHaveBeenCalledWith('after unmount', '*');
  expect(f.host.removeEventListener).toHaveBeenCalledTimes(1);
});
