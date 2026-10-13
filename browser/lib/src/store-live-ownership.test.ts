import { describe, expect, it, vi } from 'vitest';
import { Store, type Agent } from './index.js';

const subject = 'atomic:private-drive';

function setup() {
  const store = new Store({ serverUrl: 'https://example.com' });
  const socket = {
    subscribeResource: vi.fn(),
    unsubscribeResource: vi.fn(),
  };
  vi.spyOn(store, 'getWebSocketForSubject').mockReturnValue(socket as never);

  return { store, socket };
}

describe('live subscription ownership', () => {
  it('releases a holder at most once', () => {
    const { store, socket } = setup();
    const releaseA = store.subscribeLive(subject);
    const releaseB = store.subscribeLive(subject);
    releaseA();
    releaseA();
    expect(socket.unsubscribeResource).not.toHaveBeenCalled();
    expect(store.liveSubjects.get(subject)).toBe(1);
    releaseB();
    expect(socket.unsubscribeResource).toHaveBeenCalledExactlyOnceWith(subject);
  });

  it('revokes the old account and fences its delayed release', () => {
    const { store, socket } = setup();
    store.setAgent({ subject: 'atomic:agent:previous' } as Agent);
    const releaseOld = store.subscribeLive(subject);
    store.setAgent({ subject: 'atomic:agent:next' } as Agent);
    expect(store.liveSubjects.size).toBe(0);
    expect(socket.unsubscribeResource).toHaveBeenCalledExactlyOnceWith(subject);
    const releaseNew = store.subscribeLive(subject);
    socket.unsubscribeResource.mockClear();
    releaseOld();
    expect(socket.unsubscribeResource).not.toHaveBeenCalled();
    expect(store.liveSubjects.get(subject)).toBe(1);
    releaseNew();
    expect(socket.unsubscribeResource).toHaveBeenCalledExactlyOnceWith(subject);
  });

  it('retains anonymous live holders through first login', () => {
    const { store, socket } = setup();
    const release = store.subscribeLive(subject);
    store.setAgent({ subject: 'atomic:agent:first' } as Agent);
    expect(store.liveSubjects.get(subject)).toBe(1);
    expect(socket.unsubscribeResource).not.toHaveBeenCalled();
    release();
    expect(socket.unsubscribeResource).toHaveBeenCalledExactlyOnceWith(subject);
  });
});
