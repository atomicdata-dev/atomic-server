import { useNumber } from '@tomic/react';
import { InputProps } from './ResourceField';
import { useValidation } from './formValidation/useValidation';
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
  const [err, setErr, onBlur] = useValidation();
  const [value, setValue] = useNumber(resource, property.subject, {
    commit,
    validate: false,
  });

  const [localDate, handleChange] = useDateTimeInput(
    value,
    (time: number | undefined) => {
      if (required && time === undefined) {
        setErr('Required');
        setValue(undefined);
      } else {
        setErr(undefined);
        setValue(time);
      }
    },
  );

  return (
    <Wrapper>
      <StyledInputWrapper $invalid={!!err}>
        <InputStyled
          type='datetime-local'
          value={localDate}
          required={required}
          onChange={handleChange}
          onBlur={onBlur}
          {...props}
        />
      </StyledInputWrapper>
      {err && <ErrorChipInput>{err}</ErrorChipInput>}
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
