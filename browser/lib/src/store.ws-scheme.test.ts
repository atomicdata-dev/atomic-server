import { afterEach, describe, expect, it, vi } from 'vitest';
import { Store } from './store.js';
import type { WSClient } from './websockets.js';

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.setItem('ws-disconnected', '1');
});

function storeWithSocket(serverUrl: string) {
  const store = new Store({ serverUrl });
  const socket = { id: 'the-socket' } as unknown as WSClient;
  (store as unknown as { webSockets: Map<string, WSClient> }).webSockets.set(
    new URL(serverUrl).origin,
    socket,
  );

  return { store, socket };
}

describe('Store.getWebSocketForSubject behind a TLS-terminating proxy', () => {
  it('uses the server socket for an http:// subject of an https:// server, and says so once', () => {
    const { store, socket } = storeWithSocket('https://atomic.example.de');
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

    const subject = 'http://atomic.example.de/query?property=x';
    expect(store.getWebSocketForSubject(subject)).toBe(socket);
    expect(store.getWebSocketForSubject(subject)).toBe(socket);

    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0][0]).toContain('ATOMIC_SERVER_URL');
  });

  it('does not borrow the server socket for a different host', () => {
    const { store } = storeWithSocket('https://atomic.example.de');
    vi.spyOn(console, 'warn').mockImplementation(() => undefined);

    expect(
      store.getWebSocketForSubject('http://other.example.de/doc'),
    ).toBeUndefined();
  });

  it('is silent when the origin already matches', () => {
    const { store, socket } = storeWithSocket('https://atomic.example.de');
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

    expect(store.getWebSocketForSubject('https://atomic.example.de/doc')).toBe(
      socket,
    );
    expect(warn).not.toHaveBeenCalled();
  });
});
