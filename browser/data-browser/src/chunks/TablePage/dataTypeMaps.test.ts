// @wc-ignore-file
import { describe, expect, it } from 'vitest';
import { Datatype } from '@tomic/react';
import { appendStringToType, resolvePasteValue } from './dataTypeMaps';

describe('appendStringToType (#1825)', () => {
  it('never makes NaN of text that is not a number', () => {
    expect(
      appendStringToType(undefined, 'a', Datatype.INTEGER),
    ).toBeUndefined();
    expect(appendStringToType(3, 'a', Datatype.INTEGER)).toBe(3);
    expect(appendStringToType(undefined, 'x', Datatype.FLOAT)).toBeUndefined();
    expect(
      appendStringToType(undefined, '12abc', Datatype.INTEGER),
    ).toBeUndefined();
  });

  it('reads whole numbers', () => {
    expect(appendStringToType(undefined, '7', Datatype.INTEGER)).toBe(7);
    expect(appendStringToType(undefined, '-42', Datatype.INTEGER)).toBe(-42);
    expect(appendStringToType(undefined, '1,5', Datatype.FLOAT)).toBe(1.5);
    expect(appendStringToType(undefined, '-.25', Datatype.FLOAT)).toBe(-0.25);
  });

  it('stores a slug the way the slug editor does', () => {
    expect(appendStringToType(undefined, 'A', Datatype.SLUG)).toBe('a');
    expect(appendStringToType(undefined, 'My page', Datatype.SLUG)).toBe(
      'my-page',
    );
  });

  it('stores nothing for a character that is no value of the type', () => {
    for (const datatype of [
      Datatype.ATOMIC_URL,
      Datatype.RESOURCEARRAY,
      Datatype.BOOLEAN,
      Datatype.JSON,
      Datatype.DATE,
    ]) {
      expect(appendStringToType(undefined, 'a', datatype)).toBeUndefined();
    }
  });
});

describe('resolvePasteValue', () => {
  it('sets a value the column type can read', () => {
    expect(resolvePasteValue('2026-09-25', Datatype.DATE)).toEqual({
      action: 'set',
      value: '2026-09-25',
    });
    expect(resolvePasteValue('7', Datatype.INTEGER)).toEqual({
      action: 'set',
      value: 7,
    });
    expect(resolvePasteValue('false', Datatype.BOOLEAN)).toEqual({
      action: 'set',
      value: false,
    });
  });

  it('clears the property for an empty clipboard cell instead of setting undefined', () => {
    for (const datatype of [
      Datatype.DATE,
      Datatype.TIMESTAMP,
      Datatype.INTEGER,
      Datatype.FLOAT,
      Datatype.BOOLEAN,
      Datatype.ATOMIC_URL,
      Datatype.RESOURCEARRAY,
    ]) {
      expect(resolvePasteValue('', datatype)).toEqual({ action: 'clear' });
      expect(resolvePasteValue('  ', datatype)).toEqual({ action: 'clear' });
    }
  });

  it('skips text the column type cannot read, keeping the stored value', () => {
    expect(resolvePasteValue('not a date', Datatype.DATE)).toEqual({
      action: 'skip',
    });
    expect(resolvePasteValue('abc', Datatype.TIMESTAMP)).toEqual({
      action: 'skip',
    });
    expect(resolvePasteValue('maybe', Datatype.BOOLEAN)).toEqual({
      action: 'skip',
    });
  });

  it('never yields a set with an undefined value', () => {
    for (const datatype of Object.values(Datatype)) {
      for (const data of ['', 'x', '1', '2026-01-01', 'true']) {
        const result = resolvePasteValue(data, datatype);

        if (result.action === 'set') {
          expect(result.value).not.toBeUndefined();
        }
      }
    }
  });
});
