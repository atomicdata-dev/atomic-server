// @vitest-environment jsdom
// @wc-ignore-file
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { createRequire } from 'node:module';
import type { ReactNode } from 'react';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { Store, StoreContext, collections, core } from '@tomic/react';
import { LoroLoader, type ClientDbWorker } from '@tomic/lib';
import { useDriveChats } from './useDriveChats';

/**
 * The AI Chats panel lists chats of the private drive. On a second device the
 * active drive is often another one and the connection may come up late, so the
 * list must fill once connected and the private drive must be kept live.
 */
const PRIVATE = 'did:ad:private';
const TEAM = 'did:ad:team';
const HOME = 'https://app.example.com';

afterEach(cleanup);

// jsdom looks like a browser to the Loro loader, which then fetches the wasm
// over HTTP. The node build is the same engine.
beforeAll(() => {
  (LoroLoader as unknown as { _Loro: unknown })._Loro = createRequire(
    import.meta.url,
  )('loro-crdt');
});

function device({ connected }: { connected: boolean }) {
  const store = new Store({ serverUrl: HOME, connect: false });
  store.setClientDb({
    isReady: true,
    waitForReady: async () => true,
    waitForInit: async () => undefined,
    query: vi.fn(async () => ({ subjects: [], count: 0 })),
  } as unknown as ClientDbWorker);

  const onServer = ['did:ad:c1', 'did:ad:c2'];
  const queries: URL[] = [];
  store.injectFetch(async input => {
    const url = new URL(String(input));
    queries.push(url);

    return new Response(
      JSON.stringify({
        '@id': url.href,
        [collections.properties.members]: onServer,
        [collections.properties.totalMembers]: onServer.length,
      }),
      { status: 200 },
    );
  });
  store.setDrive(TEAM);
  store.finishDriveSync(TEAM, 1, Date.now());
  store.setServerConnected(connected);

  const live = vi.fn();
  const unlive = vi.fn();
  vi.spyOn(store, 'getWebSocketForSubject').mockReturnValue({
    subscribeResource: live,
    unsubscribeResource: unlive,
    subscribeAgentProfile: vi.fn(),
    unsubscribeAgentProfile: vi.fn(),
  } as never);

  const wrapper = ({ children }: { children: ReactNode }) => (
    <StoreContext value={store}>{children}</StoreContext>
  );

  return { store, queries, live, unlive, wrapper };
}

describe('useDriveChats on a device whose active drive is not the private drive', () => {
  it('lists chats when the connection comes up after the collection stopped waiting', async () => {
    const { store, queries, wrapper } = device({ connected: false });
    vi.spyOn(store, 'waitForServerConnected').mockResolvedValue(false);
    const { result } = renderHook(() => useDriveChats(PRIVATE), { wrapper });

    // Nobody could be asked yet, so the list settles empty.
    await new Promise(r => setTimeout(r, 50));
    expect(result.current).toHaveLength(0);

    act(() => store.setServerConnected(true));

    await waitFor(() => expect(result.current).toHaveLength(2));
    expect(
      queries.some(q => q.searchParams.get('property') === core.properties.isA),
    ).toBe(true);
  });

  it('keeps receiving the private drive while open, and lets go after', async () => {
    const { store, live, unlive, wrapper } = device({ connected: true });
    const { unmount } = renderHook(() => useDriveChats(PRIVATE), { wrapper });

    await waitFor(() =>
      expect(live).toHaveBeenCalledWith(store.normalizeSubject(PRIVATE)),
    );
    unmount();
    expect(unlive).toHaveBeenCalledWith(store.normalizeSubject(PRIVATE));
  });
});
