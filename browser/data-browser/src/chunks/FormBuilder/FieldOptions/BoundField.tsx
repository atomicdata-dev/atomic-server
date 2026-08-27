import type { JSX } from 'react';
import Field from '@components/forms/Field';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import type { FieldOptionsBag } from './useFieldOptions';

interface BoundFieldProps {
  label: string;
  /** The `form-field-options` key this bound is stored under. */
  optionKey: string;
  options: FieldOptionsBag;
  setOptions: (next: FieldOptionsBag) => void;
  /** Floor for the input itself — a count bound starts at 1, a value bound
   * has none. */
  min?: number;
  helper?: string;
}

/**
 * One optional numeric setting in the options bag — a value bound (`number`,
 * `currency`), a row count (`table-input`) or a selection count
 * (`multi-select`).
 *
 * Clearing the input removes the key rather than storing `0` or `NaN`: every
 * validator on both sides reads an absent key as "no bound", so an empty
 * field has to leave one absent.
 */
export function BoundField({
  label,
  optionKey,
  options,
  setOptions,
  min,
  helper,
}: BoundFieldProps): JSX.Element {
  const stored = options[optionKey] as number | undefined;

  return (
    <Field label={label} helper={helper}>
      <InputWrapper>
        <InputStyled
          type='number'
          min={min}
          data-testid={`field-option-${optionKey}`}
          value={stored ?? ''}
          onChange={e => {
            const next = { ...options };

            if (e.target.value.trim() === '') {
              delete next[optionKey];
            } else {
              next[optionKey] = Number(e.target.value);
            }

            setOptions(next);
          }}
        />
      </InputWrapper>
    </Field>
  );
}
