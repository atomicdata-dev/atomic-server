import { useCallback } from 'react';
import { InputStyled, InputWrapper } from './InputStyles';
import { Row } from '../Row';

interface RangeInputProps {
  minValue?: number;
  maxValue?: number;
  round?: boolean;
  invalid?: boolean;
  onBlur?: () => void;
  onChange: (min: number | undefined, max: number | undefined) => void;
}

const toOptionalNum = (value: string, round: boolean): number | undefined => {
  const num = Number.parseFloat(value);

  if (Number.isNaN(num)) {
    return undefined;
  }

  return round ? Math.floor(num) : num;
};

export function validateRange(
  min: number | undefined,
  max: number | undefined,
  shouldBeRounded = false,
): string | undefined {
  let error: string | undefined = undefined;

  if (min !== undefined && shouldBeRounded) {
    error = Number.isInteger(min)
      ? undefined
      : 'Value should be a round number.';
  }

  if (max !== undefined && shouldBeRounded) {
    error = Number.isInteger(min)
      ? undefined
      : 'Value should be a round number.';
  }

  if (min !== undefined && max !== undefined) {
    error = min < max ? undefined : 'Min must be a less than max';
  }

  return error;
}

export function RangeInput({
  round = false,
  minValue,
  maxValue,
  invalid,
  onBlur,
  onChange,
}: RangeInputProps): JSX.Element {
  const handleMinChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const num = toOptionalNum(e.target.value, round);
      onChange(num, maxValue);
    },
    [onChange, maxValue],
  );

  const handleMaxChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const num = toOptionalNum(e.target.value, round);
      onChange(minValue, num);
    },
    [onChange, minValue],
  );

  return (
    <Row center gap='0.5rem'>
      <InputWrapper $invalid={invalid}>
        <InputStyled
          type='number'
          max={maxValue}
          placeholder='min'
          defaultValue={minValue}
          onBlur={onBlur}
          onChange={handleMinChange}
        />
      </InputWrapper>
      {' - '}
      <InputWrapper $invalid={invalid}>
        <InputStyled
          type='number'
          placeholder='max'
          min={minValue}
          defaultValue={maxValue}
          onBlur={onBlur}
          onChange={handleMaxChange}
        />
      </InputWrapper>
    </Row>
  );
}
