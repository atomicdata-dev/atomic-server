import { useCallback } from 'react';
import { useString, validateDatatype } from '@tomic/react';
import { InputProps } from './ResourceField';
import { ErrMessage } from './InputStyles';
import { MarkdownInput } from './MarkdownInput';
import {
  checkForInitialRequiredValue,
  useValidation,
} from './formValidation/useValidation';

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
  const { error, setError, setTouched } = useValidation(
    checkForInitialRequiredValue(value, props.required),
  );

  const handleChange = useCallback(
    (val: string) => {
      try {
        validateDatatype(val, property.datatype);
        setError(undefined);
      } catch (e) {
        setError('Invalid value');
      }

      if (props.required && (val === '' || val === undefined)) {
        setError('Required');
      }

      setValue(val);
    },
    [property.datatype, props.required, setError, setValue],
  );

  return (
    <>
      <MarkdownInput
        initialContent={value}
        id={id}
        labelId={labelId}
        onChange={handleChange}
        onBlur={setTouched}
      />
      {error && <ErrMessage>{error}</ErrMessage>}
    </>
  );
}
