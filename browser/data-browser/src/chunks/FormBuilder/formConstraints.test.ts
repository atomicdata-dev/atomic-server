import { describe, expect, it } from 'vitest';
import {
  assertOptionsTighten,
  narrowFieldOptions,
  narrowedConstraintKeywords,
  normalizeFieldOptions,
} from './formConstraints';

/** Twin of the `narrow_options` / `normalize_option_keys` tests in
 * `server/src/forms.rs`. */
describe('form limits and class constraints', () => {
  it('renames the legacy limit names, per question type', () => {
    expect(
      normalizeFieldOptions('multi-select', {
        minSelected: 1,
        maxSelected: 3,
        maxItems: 2,
      }),
    ).toEqual({ minItems: 1, maxItems: 2 });
    expect(normalizeFieldOptions('number', { min: 1, max: 5 })).toEqual({
      minimum: 1,
      maximum: 5,
    });
    expect(
      normalizeFieldOptions('table-input', { minRows: 1, maxRows: 5 }),
    ).toEqual({ minItems: 1, maxItems: 5 });
    // A rating's `max` is its number of steps.
    expect(normalizeFieldOptions('rating', { max: 7 })).toEqual({ max: 7 });
  });

  it('narrows the class constraint with the question own limits', () => {
    expect(
      narrowFieldOptions(
        'number',
        { minimum: 2, maximum: 20 },
        { minimum: 0, maximum: 10, exclusiveMinimum: -1 },
      ),
    ).toEqual({ minimum: 2, maximum: 10, exclusiveMinimum: -1 });
    expect(
      narrowFieldOptions(
        'multi-select',
        { minItems: 3, maxItems: 5 },
        { minItems: 1, maxItems: 2 },
      ),
    ).toEqual({ minItems: 2, maxItems: 2 });
    expect(
      narrowFieldOptions(
        'short-text',
        { minLength: 2 },
        { maxLength: 5, pattern: /^[a-z]+$/ },
      ),
    ).toEqual({ minLength: 2, maxLength: 5, pattern: '^[a-z]+$' });
    expect(narrowFieldOptions('email', { placeholder: 'x' }, {})).toEqual({
      placeholder: 'x',
    });
  });

  it('refuses a limit looser than the class', () => {
    expect(() =>
      assertOptionsTighten('number', { maximum: 11 }, { maximum: 10 }),
    ).toThrow('maximum cannot exceed the table column limit (10)');
    expect(() =>
      assertOptionsTighten('number', { minimum: -1 }, { minimum: 0 }),
    ).toThrow('minimum cannot be below the table column limit (0)');
    expect(() =>
      assertOptionsTighten('number', { minimum: 11 }, { maximum: 10 }),
    ).toThrow('cannot exceed');
    expect(() =>
      assertOptionsTighten(
        'number',
        { minimum: 2, maximum: 8 },
        { maximum: 10 },
      ),
    ).not.toThrow();
  });

  it('writes the narrowed limits as JSON Schema keywords', () => {
    expect(
      narrowedConstraintKeywords(
        'multi-select',
        { maxSelected: 5 },
        { enum: ['a'], maxItems: 3 },
      ),
    ).toEqual({ enum: ['a'], maxItems: 3 });
  });
});
