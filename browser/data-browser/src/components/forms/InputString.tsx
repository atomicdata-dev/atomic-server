import { useString, validateDatatype } from '@tomic/react';
import { InputProps } from './ResourceField';
import { InputStyled, InputWrapper } from './InputStyles';
import { styled } from 'styled-components';
import { ErrorChipInput } from './ErrorChip';
import {
  checkForInitialRequiredValue,
  useValidation,
} from './formValidation/useValidation';

export default function InputString({
  resource,
  property,
  commit,
  commitDebounceInterval,
  ...props
}: InputProps): JSX.Element {
  const [value, setValue] = useString(resource, property.subject, {
    commit,
    commitDebounce: commitDebounceInterval,
    validate: false,
  });

  const { error, setError, setTouched } = useValidation(
    checkForInitialRequiredValue(value, props.required),
  );

  function handleUpdate(event: React.ChangeEvent<HTMLInputElement>): void {
    const newval = event.target.value ?? undefined;
    setValue(newval);

    try {
      validateDatatype(newval, property.datatype);
      setError(undefined);
    } catch (e) {
      setError('Invalid value');
    }

    if (props.required && newval === '') {
      setError('Required');
    }
  }

  return (
    <Wrapper>
      <InputWrapper $invalid={!!error}>
        <InputStyled
          value={value === undefined ? '' : value}
          onChange={handleUpdate}
          {...props}
          onBlur={setTouched}
        />
      </InputWrapper>
      {error && <ErrorChipInput>{error}</ErrorChipInput>}
    </Wrapper>
  );
}

const Wrapper = styled.div`
  flex: 1;
  position: relative;
`;
