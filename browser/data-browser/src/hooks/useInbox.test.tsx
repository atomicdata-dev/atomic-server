// @vitest-environment jsdom
// @wc-ignore-file
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { createRequire } from 'node:module';
import React, { type ReactNode } from 'react';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  Resource,
  Store,
  StoreContext,
  collections,
  core,
  notifications,
  server,
} from '@tomic/react';
import { LoroLoader, type ClientDbWorker } from '@tomic/lib';
import { useInbox } from './useInbox';

/**
 * The Inbox lives in the private drive. On a second device the active drive is
 * often another one (a team drive), so the private drive is never synced or
 * subscribed there, and the device may open before its server connection is up.
 * The Inbox must still list what other devices recorded, and show what they
 * record while this one is open.
 */
const fixture = vi.hoisted(() => ({
  privateDrive: 'did:ad:private' as string | undefined,
}));
vi.mock('./usePrivateDrive', () => ({
  usePrivateDrive: () => ({
    privateDrive: fixture.privateDrive,
    loading: false,
  }),
}));

const HOME = 'https://app.example.com';
const PRIVATE = 'did:ad:private';
const TEAM = 'did:ad:team';

afterEach(() => {
  cleanup();
  fixture.privateDrive = 'did:ad:private';
});

// jsdom looks like a browser to the Loro loader, which then fetches the wasm
// over HTTP. The node build is the same engine.
beforeAll(() => {
  (LoroLoader as unknown as { _Loro: unknown })._Loro = createRequire(
    import.meta.url,
  )('loro-crdt');
});

async function notification(store: Store, subject: string, at: number) {
  const resource = new Resource(subject);
  await resource.set(core.properties.isA, [notifications.classes.notification]);
  await resource.set(notifications.properties.occurredAt, at);
  store.addResource(resource);

  return resource;
}

async function device({
  activeDrive,
  connected,
}: {
  activeDrive: string;
  connected: boolean;
}) {
  const store = new Store({ serverUrl: HOME, connect: false });
  // This device has nothing of the private drive locally.
  store.setClientDb({
    isReady: true,
    waitForReady: async () => true,
    waitForInit: async () => undefined,
    query: vi.fn(async () => ({ subjects: [], count: 0 })),
  } as unknown as ClientDbWorker);

  const onServer = ['did:ad:n1', 'did:ad:n2'];
  await notification(store, onServer[0], 1);
  await notification(store, onServer[1], 2);

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
  store.setDrive(activeDrive);
  store.finishDriveSync(activeDrive, 1, Date.now());
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

describe('useInbox on a device whose active drive is not the private drive', () => {
  it('lists the notifications other devices recorded', async () => {
    const { store, wrapper } = await device({
      activeDrive: TEAM,
      connected: true,
    });
    const { result } = renderHook(() => useInbox(), { wrapper });

    await waitFor(() => expect(result.current.items).toHaveLength(2));
    expect(result.current.items.map(n => n.subject)).toEqual([
      store.normalizeSubject('did:ad:n2'),
      store.normalizeSubject('did:ad:n1'),
    ]);
  });

  it('lists them when the connection comes up after the collection stopped waiting for it', async () => {
    const { store, wrapper } = await device({
      activeDrive: TEAM,
      connected: false,
    });
    // A cold start (OPFS, then AUTH) on a slow tablet outlasts the bounded
    // wait a collection gives the connection; it then settles empty.
    vi.spyOn(store, 'waitForServerConnected').mockResolvedValue(false);
    const { result } = renderHook(() => useInbox(), { wrapper });

    // The local database answered "nothing" and nobody could be asked yet.
    await waitFor(() => expect(result.current.ready).toBe(true));
    expect(result.current.items).toHaveLength(0);

    act(() => store.setServerConnected(true));

    await waitFor(() => expect(result.current.items).toHaveLength(2));
  });

  it('keeps receiving the private drive while open, and lets go after', async () => {
    const { store, live, unlive, wrapper } = await device({
      activeDrive: TEAM,
      connected: true,
    });
    const { unmount } = renderHook(() => useInbox(), { wrapper });

    await waitFor(() =>
      expect(live).toHaveBeenCalledWith(store.normalizeSubject(PRIVATE)),
    );
    unmount();
    expect(unlive).toHaveBeenCalledWith(store.normalizeSubject(PRIVATE));
  });

  it('does not touch the subscription of the active drive when that is the private drive', async () => {
    const { live, unlive, wrapper } = await device({
      activeDrive: PRIVATE,
      connected: true,
    });
    const { unmount } = renderHook(() => useInbox(), { wrapper });

    await waitFor(() => expect(live).not.toHaveBeenCalled());
    unmount();
    expect(unlive).not.toHaveBeenCalled();
  });
});

describe('inbox live sync outside the active workspace', () => {
  it('refetches missed members and cached read state on a server-only reconnect', async () => {
    const store = new Store({
      serverUrl: 'https://example.com',
      connect: false,
    });
    const privateDrive = 'atomic:personal';
    fixture.privateDrive = privateDrive;
    store.hydrateResourceFromJsonAd(
      privateDrive,
      JSON.stringify({
        '@id': privateDrive,
        [core.properties.isA]: [server.classes.drive],
      }),
    );
    store.setServerConnected(true);
    let rows = [{ subject: 'atomic:first', read: false }];
    store.injectFetch(async input => {
      const url =
        typeof input === 'string'
          ? input
          : input instanceof URL
            ? input.href
            : input.url;
      const subject = new URL(url).searchParams.get('subject') ?? url;
      const query = new URL(url).pathname.replace(/\/$/, '') === '/query';
      const row = rows.find(r => r.subject === subject);
      const json = query
        ? {
            '@id': subject,
            [core.properties.isA]: [collections.classes.collection],
            [collections.properties.members]: rows.map(r => r.subject),
            [collections.properties.totalMembers]: rows.length,
          }
        : {
            '@id': subject,
            [core.properties.isA]: [notifications.classes.notification],
            [notifications.properties.notificationSource]: `${subject}-message`,
            [notifications.properties.occurredAt]: 1,
            ...(row?.read ? { [notifications.properties.readAt]: 2 } : {}),
          };

      return new Response(JSON.stringify(json), {
        headers: { 'content-type': 'application/ad+json' },
      });
    });
    const wrapper = ({ children }: { children: React.ReactNode }) =>
      React.createElement(StoreContext.Provider, { value: store }, children);
    const { result, unmount } = renderHook(() => useInbox(), { wrapper });
    await waitFor(() => expect(result.current.unread).toBe(1));
    store.setServerConnected(false);
    rows = [
      { subject: 'atomic:first', read: true },
      { subject: 'atomic:second', read: false },
    ];
    await act(async () => {
      store.setServerConnected(true);
    });
    await waitFor(() => expect(result.current.items).toHaveLength(2));
    expect(result.current.unread).toBe(1);
    expect(
      result.current.items
        .find(r => r.subject === 'atomic:first')
        ?.get(notifications.properties.readAt),
    ).toBe(2);
    unmount();
  });

  it('counts every page and replaces the inbox when the personal drive changes', async () => {
    const store = new Store({
      serverUrl: 'https://example.com',
      connect: false,
    });
    store.setDrive('atomic:project');
    const rows = (drive: string, count: number) =>
      Array.from({ length: count }, (_, i) =>
        JSON.stringify({
          '@id': `${drive}-notification-${i}`,
          [core.properties.isA]: [notifications.classes.notification],
          ['https://atomicdata.dev/properties/drive']: drive,
          [notifications.properties.notificationSource]:
            `${drive}-message-${i}`,
          [notifications.properties.occurredAt]: i,
        }),
      );
    const all = [
      ...rows('atomic:personal', 101),
      ...rows('atomic:other-person', 1),
    ];
    store.setClientDb({
      isReady: true,
      query: async (opts: { drive?: string }) => {
        const resources = all.filter(
          r =>
            !opts.drive ||
            JSON.parse(r)['https://atomicdata.dev/properties/drive'] ===
              opts.drive,
        );

        return {
          subjects: resources.map(r => JSON.parse(r)['@id']),
          resources,
          count: resources.length,
        };
      },
      flush: async () => undefined,
    } as unknown as Parameters<Store['setClientDb']>[0]);

    for (const subject of ['atomic:personal', 'atomic:other-person']) {
      store.hydrateResourceFromJsonAd(
        subject,
        JSON.stringify({
          '@id': subject,
          [core.properties.isA]: [server.classes.drive],
        }),
      );
      store.finishDriveSync(subject, 1, Date.now());
    }

    fixture.privateDrive = 'atomic:personal';
    const wrapper = ({ children }: { children: React.ReactNode }) =>
      React.createElement(StoreContext.Provider, { value: store }, children);
    const { result, rerender, unmount } = renderHook(() => useInbox(), {
      wrapper,
    });
    await waitFor(() => expect(result.current.unread).toBe(101));
    expect(result.current.items).toHaveLength(101);
    fixture.privateDrive = 'atomic:other-person';
    rerender();
    await waitFor(() =>
      expect(result.current.items.map((r: Resource) => r.subject)).toEqual([
        'atomic:other-person-notification-0',
      ]),
    );
    expect(result.current.unread).toBe(1);
    unmount();
  });

  it('holds the personal drive subscription and releases it on identity change', async () => {
    const store = new Store({
      serverUrl: 'https://example.com',
      connect: false,
    });
    store.setDrive('atomic:project');
    store.setClientDb({
      isReady: true,
      query: async () => ({ subjects: [], resources: [], count: 0 }),
      flush: async () => undefined,
    } as unknown as Parameters<Store['setClientDb']>[0]);
    fixture.privateDrive = 'atomic:personal';

    for (const subject of ['atomic:personal', 'atomic:other-person']) {
      store.hydrateResourceFromJsonAd(
        subject,
        JSON.stringify({
          '@id': subject,
          [core.properties.isA]: [server.classes.drive],
        }),
      );
    }

    store.finishDriveSync(fixture.privateDrive, 1, Date.now());
    const unsubscribe = vi.fn();
    const subscribe = vi
      .spyOn(store, 'subscribeLive')
      .mockReturnValue(unsubscribe);
    const wrapper = ({ children }: { children: React.ReactNode }) =>
      React.createElement(StoreContext.Provider, { value: store }, children);
    const { rerender, unmount } = renderHook(() => useInbox(), { wrapper });

    await waitFor(() =>
      expect(subscribe).toHaveBeenCalledWith('atomic:personal'),
    );
    expect(subscribe).not.toHaveBeenCalledWith('atomic:project');

    fixture.privateDrive = 'atomic:other-person';
    store.finishDriveSync(fixture.privateDrive, 1, Date.now());
    rerender();
    await waitFor(() =>
      expect(subscribe).toHaveBeenCalledWith(fixture.privateDrive),
    );
    expect(unsubscribe).toHaveBeenCalledTimes(1);

    fixture.privateDrive = undefined;
    rerender();
    expect(unsubscribe).toHaveBeenCalledTimes(2);
    unmount();
    expect(unsubscribe).toHaveBeenCalledTimes(2);
  });
});
