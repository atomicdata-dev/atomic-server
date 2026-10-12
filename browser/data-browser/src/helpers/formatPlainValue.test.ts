import { describe, expect, it } from 'vitest';
import { asSubject, formatPlainValue } from '../helpers/formatPlainValue';

describe('formatPlainValue', () => {
  it('writes an object value out as text instead of passing it to React', () => {
    expect(
      formatPlainValue({ 'https://atomicdata.dev/task/v1/status': 'todo' }),
    ).toBe('{"https://atomicdata.dev/task/v1/status":"todo"}');
  });

  it('keeps strings, numbers and booleans readable', () => {
    expect(formatPlainValue('a')).toBe('a');
    expect(formatPlainValue(3)).toBe('3');
    expect(formatPlainValue(false)).toBe('false');
  });
});

describe('asSubject', () => {
  it('passes a string through', () => {
    expect(asSubject('https://example.com/a')).toBe('https://example.com/a');
  });

  it('gives nothing for a value that cannot be looked up as a subject', () => {
    expect(asSubject({ 'https://atomicdata.dev/task/v1/status': 'x' })).toBe(
      undefined,
    );
    expect(asSubject(['https://example.com/a'])).toBe(undefined);
    expect(asSubject(3)).toBe(undefined);
    expect(asSubject('')).toBe(undefined);
    expect(asSubject(null)).toBe(undefined);
    expect(asSubject(undefined)).toBe(undefined);
  });
});
