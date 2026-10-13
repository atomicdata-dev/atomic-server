// @vitest-environment jsdom
// @wc-ignore-file
import React from 'react';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import {
  core,
  LoroLoader,
  collections,
  server,
  notifications,
  Store,
  StoreContext,
  type Resource,
} from '@tomic/react';
import { useInbox } from './useInbox';

let privateDrive: string | undefined;
vi.mock('./usePrivateDrive', () => ({
  usePrivateDrive: () => ({ privateDrive, loading: false }),
}));

beforeAll(async () => {
  // Use the real browser Loro module with WASM from disk under jsdom.
  const wasm = await readFile(
    createRequire(import.meta.url).resolve('loro-crdt/web/loro_wasm_bg.wasm'),
  );
  const web = (await import('loro-crdt/web')) as unknown as {
    default: (options: { module_or_path: Uint8Array }) => Promise<unknown>;
  };
  await web.default({ module_or_path: wasm });
  await LoroLoader.initializeLoro();
});

describe('inbox live sync outside the active workspace', () => {
  it('refetches missed members and cached read state on a server-only reconnect', async () => {
    const store = new Store({
      serverUrl: 'https://example.com',
      connect: false,
    });
    privateDrive = 'atomic:personal';
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

    privateDrive = 'atomic:personal';
    const wrapper = ({ children }: { children: React.ReactNode }) =>
      React.createElement(StoreContext.Provider, { value: store }, children);
    const { result, rerender, unmount } = renderHook(() => useInbox(), {
      wrapper,
    });
    await waitFor(() => expect(result.current.unread).toBe(101));
    expect(result.current.items).toHaveLength(101);
    privateDrive = 'atomic:other-person';
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
    privateDrive = 'atomic:personal';

    for (const subject of ['atomic:personal', 'atomic:other-person']) {
      store.hydrateResourceFromJsonAd(
        subject,
        JSON.stringify({
          '@id': subject,
          [core.properties.isA]: [server.classes.drive],
        }),
      );
    }

    store.finishDriveSync(privateDrive, 1, Date.now());
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

    privateDrive = 'atomic:other-person';
    store.finishDriveSync(privateDrive, 1, Date.now());
    rerender();
    await waitFor(() => expect(subscribe).toHaveBeenCalledWith(privateDrive));
    expect(unsubscribe).toHaveBeenCalledTimes(1);

    privateDrive = undefined;
    rerender();
    expect(unsubscribe).toHaveBeenCalledTimes(2);
    unmount();
    expect(unsubscribe).toHaveBeenCalledTimes(2);
  });
});
