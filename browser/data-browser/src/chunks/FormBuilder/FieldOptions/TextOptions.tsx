import { Resource } from '@tomic/react';
import type { JSX } from 'react';
import Field from '@components/forms/Field';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { useFieldOptions, type FieldOptionsBag } from './useFieldOptions';
import { FieldPair } from './FieldPair';
import { BoundField } from './BoundField';

interface TextOptionsProps {
  field: Resource;
  /** Whether the answer's length may be bounded, i.e. `short-text` or
   * `long-text`. The shape-checked types (`email`, `url`, `phone`,
   * `country`) share this editor but not the bounds. */
  lengthBounds?: boolean;
}

export function TextOptions({
  field,
  lengthBounds,
}: TextOptionsProps): JSX.Element {
  const [options, setOptions] = useFieldOptions(field);
  const placeholder = (options.placeholder as string | undefined) ?? '';

  return (
    <>
      <Field label='Placeholder'>
        <InputWrapper>
          <InputStyled
            value={placeholder}
            onChange={e =>
              setOptions({ ...options, placeholder: e.target.value })
            }
          />
        </InputWrapper>
      </Field>
      {lengthBounds && (
        <LengthBounds options={options} setOptions={setOptions} />
      )}
    </>
  );
}

/**
 * How long an answer may be. Both bounds are optional — an unbounded text
 * question is the common case — and live in the field's own options bag
 * rather than on the mapped Property, because they constrain this question
 * rather than the column its answers land in.
 */
function LengthBounds({
  options,
  setOptions,
}: {
  options: FieldOptionsBag;
  setOptions: (next: FieldOptionsBag) => void;
}): JSX.Element {
  return (
    <FieldPair>
      <BoundField
        label='Min length'
        optionKey='minLength'
        options={options}
        setOptions={setOptions}
        min={1}
        helper='The fewest characters an answer may carry. An unanswered question still counts as unanswered rather than as too short — that is what Required is for.'
      />
      <BoundField
        label='Max length'
        optionKey='maxLength'
        options={options}
        setOptions={setOptions}
        min={1}
        helper='The most characters an answer may carry. Going over is shown as an error rather than blocked, but the form cannot be submitted until it is back under.'
      />
    </FieldPair>
  );
}
