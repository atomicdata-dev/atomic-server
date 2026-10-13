import { describe, it, expect } from 'vitest';
import { dataBrowser, migratedEntryKey } from '@tomic/react';
import {
  CHAT_LOG_CAPACITY,
  hideMigrated,
  isFollowEntry,
  pageWithRoom,
  parseEntryId,
  toEntryId,
  windowChat,
  type Timed,
} from './chatLog';

const t = (id: string, at: number): Timed => ({ id, at });

describe('entry ids', () => {
  it('round-trips a page subject and an entry key', () => {
    const id = toEntryId('did:ad:abc', '19e0a1b2c3d-0a1b2c3d');
    expect(id).toBe('did:ad:abc#19e0a1b2c3d-0a1b2c3d');
    expect(parseEntryId(id)).toEqual({
      page: 'did:ad:abc',
      key: '19e0a1b2c3d-0a1b2c3d',
    });
  });

  it('does not take an old Message subject for an entry', () => {
    expect(parseEntryId('did:ad:abc')).toBeUndefined();
    expect(parseEntryId('https://example.com/msg#section')).toBeUndefined();
  });
});

describe('windowChat', () => {
  it('lists only old messages as they are', () => {
    const old = [t('m1', 1), t('m2', 2)];
    expect(
      windowChat({ old, oldTotal: 2, log: [], unloadedPages: 0, visible: 50 }),
    ).toEqual({ ids: ['m1', 'm2'], olderCount: 0 });
  });

  it('merges old messages and entries by time', () => {
    const result = windowChat({
      old: [t('m1', 10), t('m2', 30)],
      oldTotal: 2,
      log: [t('p#a', 20), t('p#b', 40)],
      unloadedPages: 0,
      visible: 50,
    });
    expect(result.ids).toEqual(['m1', 'p#a', 'm2', 'p#b']);
    expect(result.olderCount).toBe(0);
  });

  it('orders entries of different pages and equal times stably', () => {
    const result = windowChat({
      old: [],
      oldTotal: 0,
      log: [t('p2#a', 5), t('p1#z', 5), t('p1#a', 1)],
      unloadedPages: 0,
      visible: 50,
    });
    expect(result.ids).toEqual(['p1#a', 'p1#z', 'p2#a']);
  });

  it('shows the newest and counts the older ones, in all sources', () => {
    const result = windowChat({
      old: [t('m3', 3), t('m4', 4)],
      oldTotal: 4,
      log: [t('p#5', 5), t('p#6', 6), t('p#7', 7)],
      unloadedPages: 0,
      visible: 3,
    });
    expect(result.ids).toEqual(['p#5', 'p#6', 'p#7']);
    // 2 old messages that were not even listed + 2 listed but outside the window.
    expect(result.olderCount).toBe(4);
  });

  it('counts a page that was not loaded as at least one older message', () => {
    const result = windowChat({
      old: [],
      oldTotal: 0,
      log: [t('p#2', 2)],
      unloadedPages: 2,
      visible: 1,
    });
    expect(result).toEqual({ ids: ['p#2'], olderCount: 2 });
  });

  it('grows the window by asking for more', () => {
    const log = Array.from({ length: 120 }, (_, i) => t(`p#${i}`, i));
    const first = windowChat({
      old: [],
      oldTotal: 0,
      log,
      unloadedPages: 0,
      visible: 50,
    });
    const second = windowChat({
      old: [],
      oldTotal: 0,
      log,
      unloadedPages: 0,
      visible: 100,
    });
    expect(first.ids).toHaveLength(50);
    expect(first.olderCount).toBe(70);
    expect(second.ids).toHaveLength(100);
    expect(second.olderCount).toBe(20);
    expect(second.ids.at(-1)).toBe('p#119');
  });
});

describe('pageWithRoom', () => {
  const page = (subject: string, entries: number, createdAt: number) => ({
    subject,
    entries,
    createdAt,
  });

  it('is undefined without pages: the first message creates one', () => {
    expect(pageWithRoom([])).toBeUndefined();
  });

  it('takes the newest page while it has room', () => {
    expect(pageWithRoom([page('a', 10, 1), page('b', 3, 2)])).toBe('b');
  });

  it('starts a new page when the newest is full', () => {
    // An older page with room is not refilled: its tail is history.
    expect(
      pageWithRoom([page('a', 10, 1), page('b', CHAT_LOG_CAPACITY, 2)]),
    ).toBeUndefined();
  });
});

describe('hideMigrated', () => {
  it('hides an old Message whose entry key is in a page, and counts it', () => {
    const old = [t('did:ad:aaa', 1000), t('did:ad:bbb', 2000)];
    const keys = new Set([migratedEntryKey(1000, 'did:ad:aaa')]);

    expect(hideMigrated(old, keys)).toEqual({
      shown: [t('did:ad:bbb', 2000)],
      hidden: 1,
    });
  });

  it('keeps a message with the same hash but another time, and another id', () => {
    const old = [t('did:ad:aaa', 1000)];

    expect(
      hideMigrated(old, new Set([migratedEntryKey(1001, 'did:ad:aaa')])).hidden,
    ).toBe(0);
    expect(
      hideMigrated(old, new Set([migratedEntryKey(1000, 'did:ad:other')]))
        .hidden,
    ).toBe(0);
  });

  it('recognises the copy in either spelling of the subject', () => {
    const keys = new Set([migratedEntryKey(5, 'atomic:aaa')]);

    expect(hideMigrated([t('did:ad:aaa?drive=x', 5)], keys).hidden).toBe(1);
  });
});

describe('isFollowEntry', () => {
  it('reads the follow event kind', () => {
    expect(isFollowEntry({ k: dataBrowser.classes.followEvent })).toBe(true);
    expect(isFollowEntry({ k: [dataBrowser.classes.followEvent] })).toBe(true);
    expect(isFollowEntry({})).toBe(false);
    expect(isFollowEntry(undefined)).toBe(false);
  });
});
