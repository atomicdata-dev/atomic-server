import { useState } from 'react';
import { useString } from '@tomic/react';
import { InputProps } from './ResourceField';
import { ErrMessage } from './InputStyles';
import { MarkdownInput } from './MarkdownInput';

export default function InputMarkdown({
  resource,
  property,
  commit,
  id,
  labelId,
}: InputProps): JSX.Element {
  const [err, setErr] = useState<Error | undefined>(undefined);
  const [value, setValue] = useString(resource, property.subject, {
    handleValidationError: setErr,
    commit: commit,
  });

  const handleChange = (val: string) => {
    setValue(val);
  };

  return (
    <>
      <MarkdownInput
        initialContent={value}
        onChange={handleChange}
        id={id}
        labelId={labelId}
      />
      {value !== '' && err && <ErrMessage>{err.message}</ErrMessage>}
      {value === '' && <ErrMessage>Required</ErrMessage>}
    </>
  );
}
