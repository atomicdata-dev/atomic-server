import { describe, expect, it } from 'vitest';
import {
  selectionHint,
  validateFieldValue,
  validatePage,
} from './validation.js';
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

/**
 * Choice answers are option *subjects*, not labels — the mapped column is a
 * SelectProperty whose `allowsOnly` holds the Tags. Mirrors
 * `dropdowns_enforce_option_membership` in `server/src/forms.rs`.
 */
describe('choice option membership', () => {
  const tag = (label: string) => `did:ad:tag:${label}`;
  const choice = (type: FieldBlock['type']): FieldBlock => ({
    ...field(type, 'Pick'),
    options: {
      options: [
        { value: tag('A'), label: 'A' },
        { value: tag('B'), label: 'B' },
      ],
    },
  });

  it('accepts a subject the question offers', () => {
    expect(validateFieldValue(choice('dropdown'), tag('A'))).toBeNull();
    expect(
      validateFieldValue(choice('dropdown-multi'), [tag('A'), tag('B')]),
    ).toBeNull();
  });

  it('rejects a subject it does not', () => {
    expect(validateFieldValue(choice('dropdown'), tag('C'))).toBe(
      'Not one of the allowed options',
    );
    expect(
      validateFieldValue(choice('dropdown-multi'), [tag('A'), tag('C')]),
    ).toBe('Not one of the allowed options');
  });

  it('rejects a label, which is display text rather than an answer', () => {
    expect(validateFieldValue(choice('radio'), 'A')).toBe(
      'Not one of the allowed options',
    );
  });

  // Fails closed, unlike the other validators: an empty list means the
  // question offers nothing, not that anything goes.
  it('allows nothing when the question has no options', () => {
    expect(validateFieldValue(field('dropdown', 'Pick'), tag('A'))).toBe(
      'Not one of the allowed options',
    );
  });
});

/**
 * How many options a multi-pick question accepts. Mirrors
 * `multi_picks_enforce_selection_bounds` in `server/src/forms.rs`.
 */
describe('multi-select selection bounds', () => {
  const tag = (label: string) => `did:ad:tag:${label}`;
  const bounded = (bounds: {
    minSelected?: number;
    maxSelected?: number;
  }): FieldBlock => ({
    ...field('multi-select', 'Pick'),
    options: {
      options: ['A', 'B', 'C'].map(label => ({ value: tag(label), label })),
      ...bounds,
    },
  });

  it('accepts an answer inside the bounds', () => {
    expect(
      validateFieldValue(bounded({ minSelected: 2, maxSelected: 3 }), [
        tag('A'),
        tag('B'),
      ]),
    ).toBeNull();
  });

  it('rejects too few and too many', () => {
    expect(validateFieldValue(bounded({ minSelected: 2 }), [tag('A')])).toBe(
      'Please select at least 2 option(s)',
    );
    expect(
      validateFieldValue(bounded({ maxSelected: 2 }), [
        tag('A'),
        tag('B'),
        tag('C'),
      ]),
    ).toBe('At most 2 option(s) allowed');
  });

  it('checks membership before counting', () => {
    expect(
      validateFieldValue(bounded({ maxSelected: 1 }), [tag('A'), tag('X')]),
    ).toBe('Not one of the allowed options');
  });

  // A minimum bounds an answer; it does not make one mandatory. That is
  // `required`'s job, and the two produce different messages.
  it('leaves an empty answer unanswered rather than short', () => {
    const min = bounded({ minSelected: 2 });
    expect(validateFieldValue(min, [])).toBeNull();

    const page = (required: boolean) => ({
      version: 1 as const,
      id: 'f',
      name: 'Form',
      settings: {},
      styling: {},
      honeypotField: 'hp',
      pages: [{ blocks: [{ ...min, required }] }],
    });

    expect(validatePage(page(false), 0, { [min.mapsTo]: [] }).errors).toEqual(
      {},
    );
    expect(validatePage(page(true), 0, { [min.mapsTo]: [] }).errors).toEqual({
      [min.mapsTo]: 'This field is required',
    });
  });

  it('ignores bounds a hand-edited bag left unusable', () => {
    const junk = bounded({
      minSelected: 'two' as unknown as number,
      maxSelected: 0,
    });
    expect(validateFieldValue(junk, [tag('A')])).toBeNull();
    expect(selectionHint(junk.options)).toBeUndefined();
  });

  it('describes the bounds in one line for the visitor', () => {
    expect(selectionHint({ maxSelected: 3 })).toBe('Select up to 3 options');
    expect(selectionHint({ minSelected: 1 })).toBe('Select at least 1 option');
    expect(selectionHint({ minSelected: 2, maxSelected: 2 })).toBe(
      'Select exactly 2 options',
    );
    expect(selectionHint({ minSelected: 2, maxSelected: 4 })).toBe(
      'Select between 2 and 4 options',
    );
    expect(selectionHint({})).toBeUndefined();
  });
});
