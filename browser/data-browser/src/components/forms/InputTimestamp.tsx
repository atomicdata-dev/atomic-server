import { useNumber } from '@tomic/react';
import { InputProps } from './ResourceField';
import {
  checkForInitialRequiredValue,
  useValidation,
} from './formValidation/useValidation';
import { styled } from 'styled-components';
import { ErrorChipInput } from './ErrorChip';
import { InputStyled, InputWrapper } from './InputStyles';
import { useDateTimeInput } from './hooks/useDateTimeInput';

export function InputTimestamp({
  resource,
  property,
  commit,
  required,
  ...props
}: InputProps): React.JSX.Element {
  const [value, setValue] = useNumber(resource, property.subject, {
    commit,
    validate: false,
  });

  const { error, setError, setTouched } = useValidation(
    checkForInitialRequiredValue(value, required),
  );

  const [localDate, handleChange] = useDateTimeInput(
    value,
    (time: number | undefined) => {
      if (required && time === undefined) {
        setError('Required');
        setValue(undefined);
      } else {
        setError(undefined);
        setValue(time);
      }
    },
  );

  return (
    <Wrapper>
      <StyledInputWrapper $invalid={!!error}>
        <InputStyled
          type='datetime-local'
          value={localDate}
          required={required}
          onChange={handleChange}
          onBlur={setTouched}
          {...props}
        />
      </StyledInputWrapper>
      {error && <ErrorChipInput>{error}</ErrorChipInput>}
    </Wrapper>
  );
}

const Wrapper = styled.div`
  flex: 1;
  position: relative;
`;

const StyledInputWrapper = styled(InputWrapper)`
  width: min-content;
`;
