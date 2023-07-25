import React, { useState } from 'react';
import { useNumber } from '@tomic/react';
import { InputProps } from './ResourceField';
import { ErrMessage, InputStyled, InputWrapper } from './InputStyles';

export default function InputNumber({
  resource,
  property,
  ...props
}: InputProps): JSX.Element {
  const [err, setErr] = useState<Error | undefined>(undefined);
  const [value, setValue] = useNumber(resource, property.subject, {
    handleValidationError: setErr,
  });

  function handleUpdate(e) {
    if (e.target.value === '') {
      setValue(undefined);

      return;
    }

    const newval = +e.target.value;
    // I pass the error setter for validation purposes
    setValue(newval);
  }

  return (
    <>
      <InputWrapper>
        <InputStyled
          placeholder='Enter a number...'
          type='number'
          value={value === undefined ? '' : Number.isNaN(value) ? '' : value}
          onChange={handleUpdate}
          {...props}
        />
      </InputWrapper>
      {value !== undefined && err && <ErrMessage>{err.message}</ErrMessage>}
      {value === undefined && <ErrMessage>Required</ErrMessage>}
    </>
  );
}
