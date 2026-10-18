import { renderHook, waitFor } from '@testing-library/react';
import type { Store } from '@tomic/lib';
import { createElement, useEffect, type ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { StoreContext } from './hooks.js';
import { useChildren } from './useChildren.js';

/**
 * A stand-in for the collection of one parent. While `stale`, reads come back
 * with undefined slots (members the page does not hold yet) until `refresh()`.
 */
class FakeCollection {
  public refreshed = false;
  public stale = false;

  public constructor(
    public readonly value: string,
    private readonly children: string[],
  ) {}

  public get totalMembers() {
    return this.children.length;
  }

  public waitForReady = async () => {};

  public refresh = async () => {
    this.refreshed = true;
    this.stale = false;
  };

  public getMemberWithIndex = async (i: number) =>
    this.stale ? undefined : this.children[i];
}

const collections = new Map<string, FakeCollection>();
// What `useCollection` hands out for a parent. Like the real one it can keep
// showing the previous parent's collection until the new one is ready.
let lagging: { for: string; showing: string } | undefined;

vi.mock('./useCollection.js', () => ({
  useCollection: ({ value }: { value: string | undefined }) => {
    const parent = value ?? '';
    const shown = lagging?.for === parent ? lagging.showing : parent;

    return {
      collection: collections.get(shown) ?? new FakeCollection(parent, []),
      ready: shown === parent,
    };
  },
}));

const store = {
  on: () => () => {},
  isDestroyed: () => false,
  getResource: async () => ({
    get: () => undefined,
    getCreatedAt: () => 0,
  }),
} as unknown as Store;

const wrapper = ({ children }: { children: ReactNode }) =>
  createElement(StoreContext.Provider, { value: store }, children);

const A = 'https://example.com/A';
const B = 'https://example.com/B';
const aChildren = [
  'https://example.com/a1',
  'https://example.com/a2',
  'https://example.com/a3',
];
const bChildren = ['https://example.com/b1'];

describe('useChildren across parents', () => {
  beforeEach(() => {
    lagging = undefined;
    collections.clear();
    collections.set(A, new FakeCollection(A, aChildren));
    collections.set(B, new FakeCollection(B, bChildren));
  });

  it('recovers A children after A -> B -> A when the first read of A has undefined slots', async () => {
    const { result, rerender } = renderHook(
      ({ parent }: { parent: string }) => useChildren(parent, { limit: 10 }),
      { wrapper, initialProps: { parent: A } },
    );
    await waitFor(() => expect(result.current.subjects).toEqual(aChildren));

    rerender({ parent: B });
    await waitFor(() => expect(result.current.subjects).toEqual(bChildren));

    // Back on A, its cached page is older than the member count.
    collections.get(A)!.stale = true;
    rerender({ parent: A });

    await waitFor(() => expect(result.current.subjects).toEqual(aChildren));
    expect(collections.get(A)!.refreshed).toBe(true);
  });

  it('does not show the previous parent children while the new parent loads', async () => {
    const seen: string[][] = [];
    const { result, rerender } = renderHook(
      ({ parent }: { parent: string }) => {
        const r = useChildren(parent, { limit: 10 });
        // Committed renders only: React throws away a render that set state.
        useEffect(() => {
          seen.push([parent, ...r.subjects]);
        });

        return r;
      },
      { wrapper, initialProps: { parent: A } },
    );
    await waitFor(() => expect(result.current.subjects).toEqual(aChildren));

    // B's collection is not ready: the hook still gets A's.
    lagging = { for: B, showing: A };
    seen.length = 0;
    rerender({ parent: B });
    await new Promise(resolve => setTimeout(resolve, 50));

    for (const [parent, ...subjects] of seen) {
      if (parent === B) {
        expect(subjects).toEqual([]);
      }
    }

    lagging = undefined;
    rerender({ parent: B });
    await waitFor(() => expect(result.current.subjects).toEqual(bChildren));
  });
});
