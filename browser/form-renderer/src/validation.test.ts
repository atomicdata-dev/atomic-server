import { describe, expect, it } from 'vitest';
import { validateFieldValue } from './validation.js';
import { COUNTRY_CODES, countryName, countryOptions } from './countries.js';
import type { FieldBlock } from './types.js';

const field = (type: FieldBlock['type'], label: string): FieldBlock => ({
  kind: 'field',
  mapsTo: `https://example.com/properties/${type}`,
  label,
  type,
  required: false,
  options: {},
});

const phoneField = field('phone', 'Phone number');

/**
 * The phone rule is the one place this validator is deliberately *stricter*
 * than `is_valid_phone` in `server/src/forms.rs`: values in the E.164 shape
 * the input produces get a real length check, everything else keeps the
 * server's loose rule. Anything accepted here must still pass the server.
 */
describe('phone validation', () => {
  it('accepts the E.164 output of the phone input', () => {
    for (const good of ['+31612345678', '+14155552671', '+6421234567']) {
      expect(validateFieldValue(phoneField, good)).toBeNull();
    }
  });

  it('rejects a half-typed international number', () => {
    expect(validateFieldValue(phoneField, '+3161')).toBe(
      'Not a valid phone number',
    );
  });

  it('still accepts loosely formatted national numbers', () => {
    for (const good of ['0201234567', '(020) 123-4567', '+31 6 1234 5678']) {
      expect(validateFieldValue(phoneField, good)).toBeNull();
    }
  });

  it('rejects junk', () => {
    expect(validateFieldValue(phoneField, 'call me')).toBe(
      'Not a valid phone number',
    );
  });

  it('treats an empty value as unanswered, not invalid', () => {
    expect(validateFieldValue(phoneField, '')).toBeNull();
    expect(validateFieldValue(phoneField, undefined)).toBeNull();
  });
});

describe('country validation', () => {
  const countryField = field('country', 'Country');

  it('accepts an ISO 3166-1 alpha-2 code', () => {
    expect(validateFieldValue(countryField, 'NL')).toBeNull();
    expect(validateFieldValue(countryField, 'US')).toBeNull();
  });

  it('rejects a country name, a lowercase code and an unassigned one', () => {
    for (const bad of ['Netherlands', 'nl', 'XK', 'ZZ']) {
      expect(validateFieldValue(countryField, bad)).toBe('Not a valid country');
    }
  });
});

describe('the country list', () => {
  it('holds the 249 officially assigned ISO codes, with no duplicates', () => {
    expect(COUNTRY_CODES).toHaveLength(249);
    expect(new Set(COUNTRY_CODES).size).toBe(249);
    expect(COUNTRY_CODES.every(code => /^[A-Z]{2}$/.test(code))).toBe(true);
  });

  it('names every country, and localizes those names', () => {
    const unnamed = COUNTRY_CODES.filter(code => countryName(code) === code);
    expect(unnamed).toEqual([]);
    expect(countryName('NL', 'en')).toBe('Netherlands');
    expect(countryName('NL', 'nl')).toBe('Nederland');
  });

  it('falls back to the raw value for something that is not a country', () => {
    expect(countryName('Neverland')).toBe('Neverland');
  });

  it('sorts options by localized name, not by code', () => {
    const names = countryOptions('en').map(o => o.name);
    expect([...names].sort((a, b) => a.localeCompare(b, 'en'))).toEqual(names);
    expect(countryOptions('en')[0]?.code).toBe('AF'); // Afghanistan
  });
});
