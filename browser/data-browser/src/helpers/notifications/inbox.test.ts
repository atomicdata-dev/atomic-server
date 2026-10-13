import { describe, expect, it, vi } from 'vitest';
import {
  core,
  dataBrowser,
  notifications,
  Store,
  type Resource,
} from '@tomic/react';
import {
  dedupeBySource,
  groupNotifications,
  isUnread,
  markReadAbout,
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
