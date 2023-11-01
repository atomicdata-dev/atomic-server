import React, { useState } from 'react';
import { useBoolean } from '@tomic/react';
import { InputProps } from './ResourceField';
import { ErrMessage } from './InputStyles';
import { Checkbox } from './Checkbox';

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

  return (
    <>
      <Checkbox checked={!!value} onChange={setValue} {...props} />
      {err && <ErrMessage>{err.message}</ErrMessage>}
    </>
  );
}
