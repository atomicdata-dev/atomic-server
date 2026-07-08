import { forms, Resource, useValue, type JSONValue } from '@tomic/react';
import type { JSX } from 'react';
import Field from '@components/forms/Field';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';

interface TextOptionsProps {
  field: Resource;
}

export function TextOptions({ field }: TextOptionsProps): JSX.Element {
  const [options, setOptions] = useValue(
    field,
    forms.properties.formFieldOptions,
    { commit: true },
  );

  const opts = (options as Record<string, JSONValue> | undefined) ?? {};
  const placeholder = (opts.placeholder as string | undefined) ?? '';

  return (
    <Field label='Placeholder'>
      <InputWrapper>
        <InputStyled
          value={placeholder}
          onChange={e => setOptions({ ...opts, placeholder: e.target.value })}
        />
      </InputWrapper>
    </Field>
  );
}
