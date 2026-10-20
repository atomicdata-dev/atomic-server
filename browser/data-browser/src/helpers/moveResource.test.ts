import { describe, expect, it } from 'vitest';
import { core } from '@tomic/react';
import { moveBlockedReason } from './moveResource';

// drive <- a <- b <- c ; drive <- d ; other (separate drive)
const parents: Record<string, string> = {
  a: 'drive',
  b: 'a',
  c: 'b',
  d: 'drive',
  'other-child': 'other',
};
const root = (s: string): string => (parents[s] ? root(parents[s]) : s);
const store = {
  getResourceLoading: (s: string) => ({
    get: (p: string) => (p === core.properties.parent ? parents[s] : undefined),
  }),
  driveOfSubject: root,
} as unknown as Parameters<typeof moveBlockedReason>[0];

describe('moveBlockedReason', () => {
  it('allows moving to a sibling branch', () => {
    expect(moveBlockedReason(store, 'c', 'd')).toBeUndefined();
    expect(moveBlockedReason(store, 'b', 'drive')).toBeUndefined();
  });

  it('refuses itself and descendants', () => {
    expect(moveBlockedReason(store, 'a', 'a')).toMatch(/into itself/);
    expect(moveBlockedReason(store, 'a', 'c')).toMatch(/inside it/);
  });

  it('refuses another drive until copy-moves exist', () => {
    expect(moveBlockedReason(store, 'a', 'other')).toMatch(/another drive/);
  });

  it('refuses content-addressed properties', () => {
    expect(moveBlockedReason(store, 'did:ad:prop:abc', 'd')).toMatch(
      /property/,
    );
  });
});
