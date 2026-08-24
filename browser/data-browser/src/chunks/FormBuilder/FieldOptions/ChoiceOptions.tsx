import { Resource } from '@tomic/react';
import type { JSX } from 'react';
import { StringListEditor } from './StringListEditor';
import { useFieldOptions } from './useFieldOptions';

interface ChoiceOptionsProps {
  field: Resource;
}

/** Editable list of choice labels for `radio` / `multi-select` /
 * `dropdown` / `dropdown-multi` fields. */
export function ChoiceOptions({ field }: ChoiceOptionsProps): JSX.Element {
  const [options, setOptions] = useFieldOptions(field);

  return (
    <StringListEditor
      label='Options'
      value={(options.options as string[] | undefined) ?? []}
      onChange={list => setOptions({ ...options, options: list })}
      resetKey={field.subject}
      addLabel='Add option'
      removeLabel='Remove option'
      newItemLabel={index => `Option ${index}`}
      itemTestId='choice-option-input'
    />
  );
}
