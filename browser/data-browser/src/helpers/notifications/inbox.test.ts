import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { describe, expect, it, vi } from 'vitest';
import {
  core,
  dataBrowser,
  notifications,
  Store,
  Resource,
  enableLoro,
} from '@tomic/react';
import {
  dedupeBySource,
  groupNotifications,
  isUnread,
  markReadAbout,
  markRead,
  markUnread,
  readReceipts,
} from './inbox';

const fake = (
  subject: string,
  props: {
    source?: string;
    at?: number;
    readAt?: number;
    about?: string;
    kind?: string;
    actor?: string;
  },
) =>
  ({
    subject,
    get: (prop: string) =>
      ({
        [notifications.properties.notificationSource]: props.source,
        [notifications.properties.occurredAt]: props.at,
        [notifications.properties.readAt]: props.readAt,
        [dataBrowser.properties.about]: props.about,
        [notifications.properties.notificationKind]: props.kind,
        [notifications.properties.actor]: props.actor,
      })[prop],
    getCreatedAt: () => undefined,
  }) as unknown as Resource;

describe('dedupeBySource', () => {
  it('sorts newest first', () => {
    const list = dedupeBySource([
      fake('a', { source: 'm1', at: 1 }),
      fake('b', { source: 'm2', at: 3 }),
      fake('c', { source: 'm3', at: 2 }),
    ]);

    expect(list.map(n => n.subject)).toEqual(['b', 'c', 'a']);
  });

  it('shows one item per source, read if any copy is', () => {
    const list = dedupeBySource([
      fake('phone', { source: 'm1', at: 1 }),
      fake('laptop', { source: 'm1', at: 1, readAt: 5 }),
      fake('other', { source: 'm2', at: 2 }),
    ]);

    expect(list.map(n => n.subject)).toEqual(['other', 'laptop']);
    expect(isUnread(list[1])).toBe(false);
  });
});

describe('groupNotifications', () => {
  const DAY = 24 * 60 * 60 * 1000;
  const chat = { about: 'room', kind: 'chat' };

  it('groups unread messages about one thing into one row', () => {
    const groups = groupNotifications([
      fake('c', { ...chat, at: 3, actor: 'sanne' }),
      fake('b', { ...chat, at: 2, actor: 'polle' }),
      fake('a', { ...chat, at: 1, actor: 'sanne' }),
      fake('x', { about: 'doc', kind: 'comment', at: 1, actor: 'sanne' }),
    ]);

    expect(groups.map(g => g.items.map(n => n.subject))).toEqual([
      ['c', 'b', 'a'],
      ['x'],
    ]);
    expect(groups[0].actors).toEqual(['sanne', 'polle']);
    expect(groups[0].unread).toBe(true);
  });

  it('keeps read apart from unread, and read history per day', () => {
    const groups = groupNotifications([
      fake('new', { ...chat, at: 3 * DAY }),
      fake('seen', { ...chat, at: 3 * DAY - 1, readAt: 1 }),
      fake('old', { ...chat, at: DAY, readAt: 1 }),
    ]);

    expect(groups.map(g => g.items.map(n => n.subject))).toEqual([
      ['new'],
      ['seen'],
      ['old'],
    ]);
  });
});

it('reads every page of a conversation while preserving newer arrivals', async () => {
  const store = new Store({ serverUrl: 'https://example.com', connect: false });
  const drive = 'atomic:personal';
  const resources = Array.from({ length: 102 }, (_, i) =>
    JSON.stringify({
      '@id': `atomic:notification-${i}`,
      [core.properties.isA]: [notifications.classes.notification],
      [dataBrowser.properties.about]: 'atomic:chat',
      [notifications.properties.occurredAt]: i,
      ['https://atomicdata.dev/properties/drive']: drive,
    }),
  );
  store.setDrive(drive);
  store.finishDriveSync(drive, 102, Date.now());
  store.setClientDb({
    isReady: true,
    query: async () => ({
      subjects: resources.map(r => JSON.parse(r)['@id']),
      resources,
      count: 102,
    }),
  } as unknown as Parameters<Store['setClientDb']>[0]);

  for (const text of resources) {
    store.hydrateResourceFromJsonAd(JSON.parse(text)['@id'], text);
    const r = await store.getResource(JSON.parse(text)['@id']);
    vi.spyOn(r, 'save').mockResolvedValue('persisted');
  }

  await markReadAbout(store, drive, 'atomic:chat', 100);

  for (let i = 0; i <= 100; i++) {
    expect(
      isUnread(await store.getResource(`atomic:notification-${i}`)),
      `notification ${i}`,
    ).toBe(false);
  }

  expect(isUnread(await store.getResource('atomic:notification-101'))).toBe(
    true,
  );
});

it('three replicas share read receipts despite duplicate events and offline edits', async () => {
  const wasm = await readFile(
    createRequire(import.meta.url).resolve('loro-crdt/web/loro_wasm_bg.wasm'),
  );
  const web = (await import('loro-crdt/web')) as unknown as {
    default: (options: { module_or_path: Uint8Array }) => Promise<unknown>;
  };
  await web.default({ module_or_path: wasm });
  await enableLoro();
  const replicas = await Promise.all(
    ['a', 'b', 'c'].map(async id => {
      const home = new Resource('atomic:personal');
      const item = new Resource(`atomic:copy-${id}`);
      await item.set(
        notifications.properties.notificationSource,
        'atomic:page#entry',
        false,
      );
      vi.spyOn(home, 'save').mockResolvedValue('persisted');
      vi.spyOn(item, 'save').mockResolvedValue('persisted');
      const store = {
        getAgent: () => ({ subject: 'atomic:agent:me' }),
        getIdentityGeneration: () => 1,
        privateDriveSubject: async () => home.subject,
        getResource: async (subject: string) =>
          subject === home.subject ? home : item,
      } as unknown as Store;

      return { home, item, store };
    }),
  );
  const [a, b, c] = replicas;
  const merge = (from: typeof a, to: typeof a) =>
    to.home.importLoroUpdate(
      from.home.getLoroDoc()!.export({ mode: 'snapshot' }),
    );
  await markRead(b.store, [b.item.subject]);
  merge(b, a);
  merge(b, c);
  expect(replicas.every(r => !isUnread(r.item, readReceipts(r.home)))).toBe(
    true,
  );
  await markUnread(c.store, [c.item.subject]);
  merge(c, a);
  merge(a, b);
  // B's old physical resource remains read, but the newer shared receipt wins.
  expect(isUnread(b.item)).toBe(false);
  expect(replicas.every(r => isUnread(r.item, readReceipts(r.home)))).toBe(
    true,
  );
  // Concurrent read/unread decisions converge in either merge order.
  await markRead(a.store, [a.item.subject]);
  await markUnread(b.store, [b.item.subject]);
  merge(a, c);
  merge(b, c);
  merge(c, a);
  merge(c, b);
  expect(readReceipts(a.home)).toEqual(readReceipts(b.home));
  expect(readReceipts(b.home)).toEqual(readReceipts(c.home));
});

it.each([markRead, markUnread])(
  'does not carry a delayed read decision into another identity',
  async action => {
    let generation = 1;
    let resolve!: (resource: Resource) => void;
    const pending = new Promise<Resource>(done => {
      resolve = done;
    });
    const home = new Resource('atomic:home-of-next-user');
    const save = vi.spyOn(home, 'save').mockResolvedValue('persisted');
    const store = {
      getIdentityGeneration: () => generation,
      getAgent: () => ({ subject: 'atomic:agent:next' }),
      getResource: (subject: string) =>
        subject === 'atomic:notification' ? pending : Promise.resolve(home),
      privateDriveSubject: async () => home.subject,
    } as unknown as Store;
    const operation = action(store, ['atomic:notification']);
    const rejected = expect(operation).rejects.toThrow(/session changed/i);
    generation++;
    const item = new Resource('atomic:notification');
    await item.set(
      notifications.properties.notificationSource,
      'atomic:old-user-message',
      false,
    );
    resolve(item);
    await rejected;
    expect(save).not.toHaveBeenCalled();
  },
);
