// @wc-ignore-file
import { describe, expect, it } from 'vitest';
import { mergeActivity, newestCommentTimes } from './commentActivity';

describe('newestCommentTimes', () => {
  it('keeps the newest time per resource and skips threads without about or time', () => {
    const times = newestCommentTimes([
      { about: 'did:ad:a', at: 100 },
      { about: 'did:ad:a', at: 300, by: 'did:ad:agent:x' },
      { about: 'did:ad:b', at: 200 },
      { at: 900 },
      { about: 'did:ad:c' },
    ]);

    expect(Object.fromEntries(times)).toEqual({
      'atomic:a': { at: 300, by: 'did:ad:agent:x' },
      'atomic:b': { at: 200 },
    });
  });
});

describe('mergeActivity', () => {
  it('ranks a newer comment above an edit and labels it', () => {
    const rows = mergeActivity(
      [
        { subject: 'did:ad:a', at: 100 },
        { subject: 'did:ad:b', at: 200 },
      ],
      newestCommentTimes([
        { about: 'did:ad:a', at: 300, by: 'did:ad:agent:x' },
      ]),
    );

    expect(rows).toEqual([
      { subject: 'did:ad:a', at: 300, kind: 'commented', by: 'did:ad:agent:x' },
      { subject: 'did:ad:b', at: 200, kind: 'edited' },
    ]);
  });

  it('keeps "edited" when the edit is newer than the comment', () => {
    const rows = mergeActivity(
      [{ subject: 'did:ad:a', at: 500 }],
      newestCommentTimes([{ about: 'did:ad:a', at: 300 }]),
    );

    expect(rows).toEqual([{ subject: 'did:ad:a', at: 500, kind: 'edited' }]);
  });

  it('lists an undated resource last, without a kind', () => {
    const rows = mergeActivity(
      [{ subject: 'did:ad:x' }, { subject: 'did:ad:y', at: 1 }],
      new Map(),
    );

    expect(rows.map(r => [r.subject, r.kind])).toEqual([
      ['did:ad:y', 'edited'],
      ['did:ad:x', undefined],
    ]);
  });

  it('without a Comments folder (no comment times) matches plain edit order', () => {
    const rows = mergeActivity(
      [
        { subject: 'did:ad:a', at: 1 },
        { subject: 'did:ad:b', at: 2 },
      ],
      new Map(),
    );

    expect(rows.map(r => r.subject)).toEqual(['did:ad:b', 'did:ad:a']);
    expect(rows.every(r => r.kind === 'edited')).toBe(true);
  });
});
