import { describe, expect, it } from 'vitest';
import {
  expandSubject,
  shortenRefsDeep,
  shortenSubject,
  tryExpandRef,
} from './subject-refs.js';

const DID_A = `did:ad:${'QyJIHE1kP9aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}`;
const DID_B = `did:ad:${'QyJIHE1kZZbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'}`;

describe('shortenSubject', () => {
  it('shortens did:ad subjects to #-prefixed 8-char refs', () => {
    expect(shortenSubject(DID_A)).toBe('#QyJIHE1k');
  });

  it('is idempotent for the same subject', () => {
    expect(shortenSubject(DID_A)).toBe(shortenSubject(DID_A));
  });

  it('extends the ref on prefix collision', () => {
    shortenSubject(DID_A);
    const refB = shortenSubject(DID_B);
    expect(refB).not.toBe('#QyJIHE1k');
    expect(refB.length).toBeGreaterThan('#QyJIHE1k'.length);
    expect(tryExpandRef(refB)).toBe(DID_B);
  });

  it('leaves global URLs and commit subjects untouched', () => {
    expect(shortenSubject('https://atomicdata.dev/properties/name')).toBe(
      'https://atomicdata.dev/properties/name',
    );
    expect(shortenSubject('did:ad:commit:abc')).toBe('did:ad:commit:abc');
  });
});

describe('expansion', () => {
  it('round-trips through the registry', () => {
    const ref = shortenSubject(DID_A);
    expect(tryExpandRef(ref)).toBe(DID_A);
    expect(expandSubject(ref)).toBe(DID_A);
  });

  it('passes non-refs through expandSubject', () => {
    expect(expandSubject(DID_A)).toBe(DID_A);
    expect(expandSubject('https://example.com/x')).toBe(
      'https://example.com/x',
    );
  });

  it('throws on unknown refs with a recovery hint', () => {
    expect(() => expandSubject('#zzzzzzzz')).toThrow(/older session/);
  });

  it('does not treat ordinary text as refs', () => {
    expect(tryExpandRef('#TODO')).toBeUndefined();
    expect(expandSubject('#short')).toBe('#short');
  });
});

describe('shortenRefsDeep', () => {
  it('shortens subjects in values, arrays, and object keys', () => {
    const ref = shortenSubject(DID_A);
    const input = {
      '@id': DID_A,
      related: [DID_A, 'plain text'],
      [DID_A]: 'value under a DID key',
      nested: { parent: DID_A },
    };
    expect(shortenRefsDeep(input)).toEqual({
      '@id': ref,
      related: [ref, 'plain text'],
      [ref]: 'value under a DID key',
      nested: { parent: ref },
    });
  });

  it('leaves prose containing a DID mid-sentence alone', () => {
    const text = `See ${DID_A} for details`;
    expect(shortenRefsDeep(text)).toBe(text);
  });
});

it('retains emitted refs when the module reloads in the same tab', async () => {
  const { vi } = await import('vitest');
  const storage = new Map<string, string>();
  vi.stubGlobal('sessionStorage', {
    getItem: (key: string) => storage.get(key) ?? null,
    setItem: (key: string, value: string) => storage.set(key, value),
  });
  vi.resetModules();
  const first = await import('./subject-refs.js');
  const ref = first.shortenSubject(DID_A);
  vi.resetModules();
  const reopened = await import('./subject-refs.js');
  expect(reopened.expandSubject(ref)).toBe(DID_A);
  vi.unstubAllGlobals();
});
