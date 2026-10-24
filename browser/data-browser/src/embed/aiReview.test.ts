// @wc-ignore-file
import { describe, expect, it, vi } from 'vitest';
import type { Resource } from '@tomic/react';
import { createAiReview, summarise } from './aiReview';

const res = (props: Record<string, unknown>, title = 'T') =>
  ({
    title,
    getEntries: () => Object.entries(props),
    get: (k: string) => props[k],
  }) as unknown as Resource;

describe('summarise', () => {
  it('names the changed properties, text for the document body', () => {
    expect(
      summarise(
        res({ 'x/name': 'a', 'x/description': 'd' }),
        res({ 'x/name': 'b', 'x/description': 'd', 'x/_documentContent': 'c' }),
      ),
    ).toBe(
      'Changed name, _documentContent'.replace('_documentContent', 'text'),
    );
  });

  it('cuts a long list', () => {
    const after = res({ 'x/a': 1, 'x/b': 1, 'x/c': 1, 'x/d': 1, 'x/e': 1 });

    expect(summarise(res({}), after)).toBe('Changed a, b, c and 2 more');
  });
});

describe('createAiReview', () => {
  const store = {
    getResource: async (s: string) => res({ 'x/name': s }, `Title ${s}`),
  };

  it('lists the held edits with titles and summaries', async () => {
    const review = createAiReview(store as never, {
      changes: ['a'],
      oldResources: { a: res({ 'x/name': 'old' }) },
      revertResource: vi.fn(),
      acceptChanges: vi.fn(),
    });

    expect(await review.list()).toEqual([
      { subject: 'a', title: 'Title a', summary: 'Changed name' },
    ]);
  });

  it('accepts and reverts one subject or all', async () => {
    const accept = vi.fn(async () => {});
    const revert = vi.fn();
    const review = createAiReview(store as never, {
      changes: ['a', 'b'],
      oldResources: {},
      revertResource: revert,
      acceptChanges: accept,
    });

    await review.accept('b');
    expect(accept).toHaveBeenCalledTimes(1);
    await review.revert();
    expect(revert.mock.calls).toEqual([['a'], ['b']]);
    await review.revert('zzz');
    expect(revert).toHaveBeenCalledTimes(2);
  });
});
