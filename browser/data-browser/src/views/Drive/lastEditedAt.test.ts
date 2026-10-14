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
