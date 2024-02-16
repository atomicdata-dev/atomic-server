import { InputProps } from './ResourceField';
import { useValidation } from './formValidation/useValidation';
import { styled } from 'styled-components';
import { ErrorChipInput } from './ErrorChip';
import { useString, validateDatatype } from '@tomic/react';
import { InputStyled, InputWrapper } from './InputStyles';
import { ChangeEvent } from 'react';

export function InputDate({
  resource,
  property,
  commit,
  required,
  ...props
}: InputProps): React.JSX.Element {
  const [err, setErr, onBlur] = useValidation();
  const [value, setValue] = useString(resource, property.subject, {
    commit,
    validate: false,
  });

  const handleChange = (event: ChangeEvent<HTMLInputElement>) => {
    const dateStr = event.target.value;

    if (required && dateStr) {
      setErr('Required');
      setValue(undefined);
    } else {
      try {
        validateDatatype(dateStr, property.datatype);
        setValue(dateStr);
        setErr(undefined);
      } catch (e) {
        setErr(e);
      }
    }
  };

  return (
    <Wrapper>
      <StyledInputWrapper>
        <InputStyled
          type='date'
          value={value}
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
  position: relative;
`;

const StyledInputWrapper = styled(InputWrapper)`
  width: min-content;
`;
