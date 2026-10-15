import { describe, expect, it } from 'vitest';
import { core, type Resource } from '@tomic/react';
import {
  canonicalMembers,
  dedupeByMembers,
  sameMembers,
} from './conversationMembers';

const ME = 'did:ad:agent:me';
const OTHER = 'did:ad:agent:other';
const THIRD = 'did:ad:agent:third';

const conversation = (read: string[], loading = false): Resource =>
  ({
    loading,
    get: (prop: string) => (prop === core.properties.read ? read : undefined),
  }) as unknown as Resource;

describe('member identity', () => {
  it('sees did:ad: and atomic: spellings of one agent as the same', () => {
    expect(canonicalMembers(['did:ad:agent:X', 'atomic:agent:X'])).toEqual([
      'atomic:agent:X',
    ]);
    expect(
      sameMembers(
        [ME, 'did:ad:agent:X'],
        ['atomic:agent:X', 'atomic:agent:me'],
      ),
    ).toBe(true);
    expect(sameMembers([ME, OTHER], [ME, THIRD])).toBe(false);
    expect(sameMembers([ME], [ME, OTHER])).toBe(false);
  });
});

describe('dedupeByMembers', () => {
  it('keeps the first of conversations with the same members', () => {
    const resources = new Map([
      ['a', conversation([ME, OTHER])],
      ['b', conversation(['atomic:agent:other', 'atomic:agent:me'])],
      ['c', conversation([ME, THIRD])],
    ]);
    const { subjects, twins } = dedupeByMembers(['a', 'b', 'c'], resources);

    expect(subjects).toEqual(['a', 'c']);
    expect(twins.get('a')).toEqual(['b']);
  });

  it('leaves conversations that are not loaded until they are', () => {
    const resources = new Map([
      ['a', conversation([ME, OTHER])],
      ['b', conversation([ME, OTHER], true)],
    ]);

    expect(dedupeByMembers(['a', 'b', 'missing'], resources).subjects).toEqual([
      'a',
      'b',
      'missing',
    ]);
  });

  it('keeps conversations without members', () => {
    const resources = new Map([
      ['a', conversation([])],
      ['b', conversation([])],
    ]);

    expect(dedupeByMembers(['a', 'b'], resources).subjects).toEqual(['a', 'b']);
  });
});
