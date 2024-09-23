import { InputProps } from './ResourceField';
import {
  checkForInitialRequiredValue,
  useValidation,
} from './formValidation/useValidation';
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
  const [value, setValue] = useString(resource, property.subject, {
    commit,
    validate: false,
  });
  const { error, setError, setTouched } = useValidation(
    checkForInitialRequiredValue(value, required),
  );

  const handleChange = (event: ChangeEvent<HTMLInputElement>) => {
    const dateStr = event.target.value;

    if (required && dateStr) {
      setError('Required');
      setValue(undefined);
    } else {
      try {
        validateDatatype(dateStr, property.datatype);
        setValue(dateStr);
        setError(undefined);
      } catch (e) {
        setError(e);
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
          onBlur={setTouched}
          required={required}
          {...props}
        />
      </StyledInputWrapper>
      {error && <ErrorChipInput>{error}</ErrorChipInput>}
    </Wrapper>
  );
}

const Wrapper = styled.div`
  position: relative;
`;

const StyledInputWrapper = styled(InputWrapper)`
  width: min-content;
`;
