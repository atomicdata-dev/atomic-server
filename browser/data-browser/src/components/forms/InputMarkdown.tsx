import { useCallback } from 'react';
import { useString, validateDatatype } from '@tomic/react';
import { InputProps } from './ResourceField';
import { ErrMessage } from './InputStyles';
import { MarkdownInput } from './MarkdownInput';
import { useValidation } from './formValidation/useValidation';

export default function InputMarkdown({
  resource,
  property,
  commit,
  id,
  labelId,
  ...props
}: InputProps): JSX.Element {
  const [value, setValue] = useString(resource, property.subject, {
    validate: false,
    commit: commit,
  });
  const [err, setErr, onBlur] = useValidation(
    props.required ? (!value ? 'Required' : undefined) : undefined,
  );

  const handleChange = useCallback(
    (val: string) => {
      try {
        validateDatatype(val, property.datatype);
        setErr(undefined);
      } catch (e) {
        setErr('Invalid value');
      }

      if (props.required && (val === '' || val === undefined)) {
        setErr('Required');
      }

      setValue(val);
    },
    [property.datatype, props.required, setErr, setValue],
  );

  return (
    <>
      <MarkdownInput
        initialContent={value}
        id={id}
        labelId={labelId}
        onChange={handleChange}
        onBlur={onBlur}
      />
      {err && <ErrMessage>{err}</ErrMessage>}
    </>
  );
}
