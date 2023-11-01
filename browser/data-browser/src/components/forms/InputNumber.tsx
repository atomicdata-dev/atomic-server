import React, { useState } from 'react';
import { Datatype, useNumber } from '@tomic/react';
import { InputProps } from './ResourceField';
import { ErrMessage, InputStyled, InputWrapper } from './InputStyles';

export default function InputNumber({
  resource,
  property,
  commit,
  ...props
}: InputProps): JSX.Element {
  const [err, setErr] = useState<Error | undefined>(undefined);
  const [value, setValue] = useNumber(resource, property.subject, {
    handleValidationError: setErr,
    validate: false,
    commit,
  });

  function handleUpdate(e: React.ChangeEvent<HTMLInputElement>) {
    if (e.target.value === '') {
      setValue(undefined);

      return;
    }

    const newval = +e.target.value;
    setValue(newval);
  }

  return (
    <>
      <InputWrapper>
        <InputStyled
          placeholder='Enter a number...'
          type='number'
          value={value === undefined ? '' : Number.isNaN(value) ? '' : value}
          step={property.datatype === Datatype.INTEGER ? 1 : 'any'}
          onChange={handleUpdate}
          {...props}
        />
      </InputWrapper>
      {value !== undefined && err && <ErrMessage>{err.message}</ErrMessage>}
      {value === undefined && <ErrMessage>Required</ErrMessage>}
    </>
  );
}
