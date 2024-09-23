import { useState } from 'react';
import { useString, validateDatatype } from '@tomic/react';
import { InputProps } from './ResourceField';
import { InputStyled, InputWrapper } from './InputStyles';
import { stringToSlug } from '../../helpers/stringToSlug';
import {
  checkForInitialRequiredValue,
  useValidation,
} from './formValidation/useValidation';
import { styled } from 'styled-components';
import { ErrorChipInput } from './ErrorChip';

export default function InputSlug({
  resource,
  property,
  commit,
  commitDebounceInterval,
  ...props
}: InputProps): JSX.Element {
  const [value, setValue] = useString(resource, property.subject, {
    validate: false,
    commit,
    commitDebounce: commitDebounceInterval,
  });

  const { error, setError, setTouched } = useValidation(
    checkForInitialRequiredValue(value, props.required),
  );

  const [inputValue, setInputValue] = useState(value);

  function handleUpdate(event: React.ChangeEvent<HTMLInputElement>): void {
    const newValue = stringToSlug(event.target.value);
    setInputValue(newValue);

    setError(undefined);

    try {
      if (newValue === '') {
        setValue(undefined);
      } else {
        validateDatatype(newValue, property.datatype);
        setValue(newValue);
      }
    } catch (e) {
      setError('Invalid Slug');
    }

    if (props.required && newValue === '') {
      setError('Required');
    }
  }

  return (
    <Wrapper>
      <InputWrapper $invalid={!!error}>
        <InputStyled
          value={inputValue ?? ''}
          onChange={handleUpdate}
          onBlur={setTouched}
          {...props}
        />
      </InputWrapper>
      {error && <ErrorChipInput top='2rem'>{error}</ErrorChipInput>}
    </Wrapper>
  );
}

const Wrapper = styled.div`
  flex: 1;
  position: relative;
`;
