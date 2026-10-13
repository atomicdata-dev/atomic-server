import { Resource, useNumber } from '@tomic/react';
import { useCallback, type JSX } from 'react';
import { ErrorChip } from '@components/forms/ErrorChip';
import { useValidation } from '@components/forms/formValidation/useValidation';
import { MinMaxInput, validateRange } from '@components/forms/MinMaxInput';

interface TableRangeInputProps {
  resource: Resource;
  minProp: string;
  maxProp: string;
}

export function TableRangeInput({
  resource,
  minProp,
  maxProp,
}: TableRangeInputProps): JSX.Element {
  const [minLength, setMinLength] = useNumber(resource, minProp);
  const [maxLength, setMaxLength] = useNumber(resource, maxProp);

  const { error, setError, setTouched } = useValidation();

  const handleRangeChange = useCallback(
    (min: number | undefined, max: number | undefined) => {
      setMinLength(min);
      setMaxLength(max);

      // Form state only: the range is written to the table class's
      // constraints when the dialog is confirmed.
      setError(validateRange(min, max, true));
    },
    [setMinLength, setMaxLength, setError],
  );

  return (
    <div>
      <MinMaxInput
        round
        maxValue={maxLength}
        minValue={minLength}
        invalid={!!error}
        onBlur={setTouched}
        onChange={handleRangeChange}
      />
      {error && <ErrorChip>{error}</ErrorChip>}
    </div>
  );
}
