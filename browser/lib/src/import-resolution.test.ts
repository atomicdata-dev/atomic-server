import { describe, it, expect } from 'vitest';
import {
  IMPORT_RESOLUTION,
  consolidatedImportValues,
  reviewImportResolution,
  resolvedImportSubject,
} from './import-resolution.js';
const p = 'https://atomicdata.dev/properties/';
const row = (name: string) => ({
  [p + 'parent']: 'did:ad:parent',
  [p + 'localId']: 'clockify:1',
  [p + 'isA']: ['did:ad:class'],
  [p + 'name']: name,
});
const pair = () =>
  ({ 'did:ad:a': row('A'), 'did:ad:b': row('B') }) as Record<
    string,
    Record<string, unknown>
  >;
describe('reviewed identity resolution', () => {
  it('keeps both originals and chooses the reviewed primary independent of ordering', () => {
    const rows = pair();
    rows['did:ad:a'][IMPORT_RESOLUTION] = reviewImportResolution(
      rows,
      'did:ad:a',
      'one',
    );
    expect(resolvedImportSubject(rows)).toBe('did:ad:a');
    expect(
      resolvedImportSubject(Object.fromEntries(Object.entries(rows).reverse())),
    ).toBe('did:ad:a');
    expect(rows['did:ad:b'][p + 'name']).toBe('B');
    rows['did:ad:a'][p + 'name'] = 'New source';
    expect(resolvedImportSubject(rows)).toBe('did:ad:a');
    rows['did:ad:b'][p + 'name'] = 'Offline edit';
    expect(resolvedImportSubject(rows)).toBeUndefined();
  });
  it('blocks unknown and missing copies', () => {
    const rows = pair();
    rows['did:ad:a'][IMPORT_RESOLUTION] = reviewImportResolution(
      rows,
      'did:ad:a',
      'one',
    );
    expect(
      resolvedImportSubject({ ...rows, 'did:ad:c': row('C') }),
    ).toBeUndefined();
    delete rows['did:ad:b'];
    expect(resolvedImportSubject(rows)).toBeUndefined();
  });
  it('requires a fresh review to supersede concurrent decisions', () => {
    const rows = pair();
    const a = reviewImportResolution(rows, 'did:ad:a', 'one');
    const b = reviewImportResolution(rows, 'did:ad:b', 'two');
    rows['did:ad:a'][IMPORT_RESOLUTION] = a;
    rows['did:ad:b'][IMPORT_RESOLUTION] = b;
    expect(resolvedImportSubject(rows)).toBeUndefined();
    rows['did:ad:b'][IMPORT_RESOLUTION] = reviewImportResolution(
      rows,
      'did:ad:b',
      'three',
    );
    expect(resolvedImportSubject(rows)).toBe('did:ad:b');
  });
  it('rejects unrelated classes or source identities', () => {
    const rows = pair();
    rows['did:ad:b'][p + 'localId'] = 'other';
    expect(() => reviewImportResolution(rows, 'did:ad:a', 'one')).toThrow(
      'same source',
    );
  });
});

it('consolidates only explicitly reviewed fields, including an empty value', () => {
  const rows = pair();
  rows['did:ad:a']['https://example.com/note'] = 'old';
  const decision = reviewImportResolution(rows, 'did:ad:a', 'merge', {
    [p + 'name']: 'did:ad:b',
    'https://example.com/note': 'did:ad:b',
  });
  const values = consolidatedImportValues(decision);
  expect(values[p + 'name']).toBe('B');
  expect(Object.hasOwn(values, 'https://example.com/note')).toBe(false);
  expect(rows['did:ad:a'][p + 'name']).toBe('A');
  expect(() =>
    reviewImportResolution(rows, 'did:ad:a', 'bad', {
      [p + 'parent']: 'did:ad:b',
    }),
  ).toThrow('protected');
  expect(() =>
    reviewImportResolution(rows, 'did:ad:a', 'bad', {
      [p + 'name']: 'did:ad:unknown',
    }),
  ).toThrow('reviewed');
});
