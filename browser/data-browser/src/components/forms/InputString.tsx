import React, { useState } from 'react';
import { useString } from '@tomic/react';
import { InputProps } from './ResourceField';
import { ErrMessage, InputStyled, InputWrapper } from './InputStyles';

export default function InputString({
  resource,
  property,
  ...props
}: InputProps): JSX.Element {
  const [err, setErr] = useState<Error | undefined>(undefined);
  const [value, setValue] = useString(resource, property.subject, {
    handleValidationError: setErr,
  });

  function handleUpdate(e: React.ChangeEvent<HTMLInputElement>): void {
    const newval = e.target.value;
    // I pass the error setter for validation purposes
    setValue(newval);
  }

  return (
    <>
      <InputWrapper>
        <InputStyled
          value={value === undefined ? '' : value}
          onChange={handleUpdate}
          {...props}
        />
      </InputWrapper>
      {value !== '' && err && <ErrMessage>{err.message}</ErrMessage>}
      {value === '' && <ErrMessage>Required</ErrMessage>}
    </>
  );
}
