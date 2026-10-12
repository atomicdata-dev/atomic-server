import { styled } from 'styled-components';
import { useState, type JSX } from 'react';
import { ErrorChip } from '@components/forms/ErrorChip';
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
  max?: number;
  /** A limit the data class already demands: the question can only tighten it,
   * so a value below it is raised to it. */
  floor?: number;
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
  max,
  floor,
  helper,
}: BoundFieldProps): JSX.Element {
  const stored = options[optionKey] as number | undefined;
  // What the last edit was held to, so the user is told rather than left
  // wondering why the typed number changed.
  const [held, setHeld] = useState<'max' | 'floor'>();

  return (
    <Field label={label} helper={helper}>
      <InputWrapper>
        <InputStyled
          type='number'
          min={floor ?? min}
          max={max}
          data-testid={`field-option-${optionKey}`}
          value={stored ?? ''}
          onChange={e => {
            const next = { ...options };

            if (e.target.value.trim() === '') {
              delete next[optionKey];
            } else {
              const typed = Number(e.target.value);
              const clamped = Math.min(
                max ?? Infinity,
                Math.max(floor ?? -Infinity, typed),
              );
              next[optionKey] = clamped;
              setHeld(
                clamped === typed
                  ? undefined
                  : typed > clamped
                    ? 'max'
                    : 'floor',
              );
            }

            if (e.target.value.trim() === '') {
              setHeld(undefined);
            }

            setOptions(next);
          }}
        />
      </InputWrapper>
      {held === 'max' && (
        <BoundError>Cannot exceed the table column limit ({max}).</BoundError>
      )}
      {held === 'floor' && (
        <BoundError>
          Cannot go below the table column minimum ({floor}).
        </BoundError>
      )}
    </Field>
  );
}

/** In normal flow under the input, so it wraps inside the column instead of
 * overflowing it and pushing the paired field out of line. */
const BoundError = styled(ErrorChip).attrs({ noMovement: true })`
  top: 0;
  display: block;
  margin-top: 0.6rem;
  font-size: 0.85em;
  overflow-wrap: anywhere;
`;
