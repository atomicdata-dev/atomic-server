import React, { useState } from 'react';
import { useBoolean } from '@tomic/react';
import { InputProps } from './ResourceField';
import { ErrMessage, InputStyled } from './InputStyles';

export default function InputBoolean({
  resource,
  property,
  commit,
  ...props
}: InputProps): JSX.Element {
  const [err, setErr] = useState<Error | undefined>(undefined);
  const [value, setValue] = useBoolean(resource, property.subject, {
    handleValidationError: setErr,
    commit,
  });

  function handleUpdate(e: React.ChangeEvent<HTMLInputElement>) {
    setValue(e.target.checked);
  }

  return (
    <>
      <InputStyled
        type='checkbox'
        checked={!!value}
        onChange={handleUpdate}
        {...props}
      />
      {err && <ErrMessage>{err.message}</ErrMessage>}
    </>
  );
}
