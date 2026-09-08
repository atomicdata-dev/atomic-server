import { describe, expect, it } from 'vitest';
import { reconcileRecord, acknowledgedBaseline } from './plugin-reconcile.js';

describe('canonical three-way sync', () => {
  it('preserves empty records during first import', () => {
    expect(reconcileRecord(undefined, undefined, {}).createLocal).toBe(true);
    expect(reconcileRecord(undefined, {}, undefined).createRemote).toBe(true);
  });
  it('merges independent field edits without losing either side', () => {
    const result = reconcileRecord(
      { title: 'old', owner: 'A' },
      { title: 'new', owner: 'A' },
      { title: 'old', owner: 'B' },
    );
    expect(result.local).toEqual({ owner: 'B' });
    expect(result.remote).toEqual({ title: 'new' });
    expect(result.conflicts).toEqual([]);
    expect(result.agreed).toBeUndefined();
  });
  it('refuses to pick a winner for concurrent edits of the same field', () => {
    const result = reconcileRecord(
      { title: 'old' },
      { title: 'local' },
      { title: 'remote' },
    );
    expect(result.conflicts).toHaveLength(1);
    expect(result.local).toEqual({});
    expect(result.remote).toEqual({});
  });
  it('requires explicit tombstones and protects edits against deletion', () => {
    expect(
      reconcileRecord({ title: 'old' }, { title: 'old' }, undefined)
        .deleteLocal,
    ).toBe(false);
    expect(
      reconcileRecord({ title: 'old' }, { title: 'old' }, null).deleteLocal,
    ).toBe(true);
    expect(
      reconcileRecord({ title: 'old' }, { title: 'new' }, null).conflicts,
    ).toHaveLength(1);
  });
  it('treats duplicate delivery as agreement without another write', () => {
    const result = reconcileRecord(
      { title: 'old' },
      { title: 'new' },
      { title: 'new' },
    );
    expect(result.agreed).toEqual({ title: 'new' });
    expect(result.local).toEqual({});
    expect(result.remote).toEqual({});
  });
  it('does not checkpoint an intended write or a normalized provider response', () => {
    expect(
      reconcileRecord({ title: 'old' }, { title: ' NEW ' }, { title: 'old' })
        .agreed,
    ).toBeUndefined();
    expect(() =>
      acknowledgedBaseline({ title: ' NEW ' }, { title: 'new' }),
    ).toThrow();
    expect(acknowledgedBaseline({ title: 'new' }, { title: 'new' })).toEqual({
      title: 'new',
    });
  });
  it('distinguishes property removal from null', () => {
    expect(
      reconcileRecord({ value: 'old' }, {}, { value: 'old' }).remote,
    ).toEqual({ value: undefined });
    expect(
      reconcileRecord({ value: 'old' }, { value: null }, { value: 'old' })
        .remote,
    ).toEqual({ value: null });
  });
});
