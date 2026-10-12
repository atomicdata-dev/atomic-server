import type { JSX } from 'react';
import { useString } from '@tomic/react';
import { InputProps } from './ResourceField';
import { ErrMessage } from './InputStyles';
import { MarkdownInput } from './MarkdownInput';
import { useValidatedInput } from './formValidation/useValidatedInput';

export default function InputMarkdown({
  resource,
  property,
  commit,
  commitDebounceInterval,
  required,
  id,
  labelId,
}: InputProps): JSX.Element {
  const [value, setValue] = useString(resource, property.subject, {
    validate: false,
    commit,
    commitDebounce: commitDebounceInterval,
  });

  const { error, setTouched, update } = useValidatedInput(value, setValue, {
    datatype: property.datatype,
    required,
  });

  // The editor is uncontrolled: `initialContent` seeds it once and it reports
  // changes back through `onChange`, so `update` never has to write back into
  // the editor.
  return (
    <>
      <MarkdownInput
        key={`${resource.subject}-${property.subject}`}
        initialContent={value}
        id={id}
        labelId={labelId}
        onChange={update}
        onBlur={setTouched}
      />
      {error && <ErrMessage>{error}</ErrMessage>}
    </>
  );
}
