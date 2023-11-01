import React, { useState } from 'react';
import { useString, validateDatatype } from '@tomic/react';
import { InputProps } from './ResourceField';
import { InputStyled, InputWrapper } from './InputStyles';
import { stringToSlug } from '../../helpers/stringToSlug';
import { useValidation } from './formValidation/useValidation';
import { styled } from 'styled-components';
import { ErrorChipInput } from './ErrorChip';

export default function InputSlug({
  resource,
  property,
  commit,
  ...props
}: InputProps): JSX.Element {
  const [err, setErr, onBlur] = useValidation();

  const [value, setValue] = useString(resource, property.subject, {
    handleValidationError: setErr,
    validate: false,
    commit,
  });

  const [inputValue, setInputValue] = useState(value);

  function handleUpdate(event: React.ChangeEvent<HTMLInputElement>): void {
    const newValue = stringToSlug(event.target.value);
    setInputValue(newValue);

    setErr(undefined);

    try {
      if (newValue === '') {
        setValue(undefined);
      } else {
        validateDatatype(newValue, property.datatype);
        setValue(newValue);
      }
    } catch (e) {
      setErr('Invalid Slug');
    }

    if (props.required && newValue === '') {
      setErr('Required');
    }
  }

  return (
    <Wrapper>
      <InputWrapper $invalid={!!err}>
        <InputStyled
          value={inputValue ?? ''}
          onChange={handleUpdate}
          onBlur={onBlur}
          {...props}
        />
      </InputWrapper>
      {err && <ErrorChipInput top='2rem'>{err}</ErrorChipInput>}
    </Wrapper>
  );
}

const Wrapper = styled.div`
  flex: 1;
  position: relative;
`;
