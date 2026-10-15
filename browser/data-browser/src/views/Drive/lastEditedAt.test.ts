// @wc-ignore-file
import { describe, expect, it, vi } from 'vitest';
import { LoroDoc } from 'loro-crdt';
import type { Resource } from '@tomic/react';
import { lastEditedAt } from './lastEditedAt';

vi.mock('loro-crdt', () => import('loro-crdt/nodejs'));

function fakeResource(doc: LoroDoc | undefined, createdAt: number): Resource {
  return {
    getLoroDoc: () => doc,
    getCreatedAt: () => createdAt,
  } as unknown as Resource;
}

describe('lastEditedAt', () => {
  it('falls back to the creation time without a doc', () => {
    expect(lastEditedAt(fakeResource(undefined, 123))).toBe(123);
  });

  it('returns the newest change timestamp in ms', () => {
    const doc = new LoroDoc();
    doc.getMap('properties').set('a', 1);
    doc.commit({ timestamp: 1_700_000_000_000 });
    doc.getMap('properties').set('a', 2);
    doc.commit({ timestamp: 1_700_000_500_000, message: 'later' });

    expect(lastEditedAt(fakeResource(doc, 5))).toBe(1_700_000_500_000);
  });

  it('reads second-resolution timestamps as ms', () => {
    const doc = new LoroDoc();
    doc.getMap('properties').set('a', 1);
    doc.commit({ timestamp: 1_700_000_000 });

    expect(lastEditedAt(fakeResource(doc, 5))).toBe(1_700_000_000_000);
  });
});

describe('lastEditedAt and hydration', () => {
  const hydrate = (doc: LoroDoc) => {
    doc.getMap('properties').set('a', 1);
    doc.commit({ timestamp: 1_800_000_000_000, message: 'c-hydration-01abc' });
  };

  it('ignores a hydration-only oplog', () => {
    const doc = new LoroDoc();
    hydrate(doc);

    expect(lastEditedAt(fakeResource(doc, undefined as never))).toBeUndefined();
    expect(lastEditedAt(fakeResource(doc, 42))).toBe(42);
  });

  it('uses a real edit made after hydration', () => {
    const doc = new LoroDoc();
    hydrate(doc);
    doc.getMap('properties').set('a', 2);
    doc.commit({ timestamp: 1_900_000_000_000, message: 'c-real' });

    expect(lastEditedAt(fakeResource(doc, 5))).toBe(1_900_000_000_000);
  });

  it('counts a message-less change (a body edit) as an edit', () => {
    const doc = new LoroDoc();
    hydrate(doc);
    doc.getMap('properties').set('a', 2);
    doc.commit({ timestamp: 1_900_000_000_000 });

    expect(lastEditedAt(fakeResource(doc, 5))).toBe(1_900_000_000_000);
  });

  it('walks back past a trailing hydration to the last real edit', () => {
    const doc = new LoroDoc();
    doc.getMap('properties').set('a', 1);
    doc.commit({ timestamp: 1_700_000_000_000, message: 'c-real' });
    doc.getMap('properties').set('a', 2);
    doc.commit({ timestamp: 1_800_000_000_000, message: 'c-hydration-01abc' });

    expect(lastEditedAt(fakeResource(doc, 5))).toBe(1_700_000_000_000);
  });
});
