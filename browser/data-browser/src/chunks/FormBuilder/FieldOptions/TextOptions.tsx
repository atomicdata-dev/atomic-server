import { Resource } from '@tomic/react';
import type { JSX } from 'react';
import Field from '@components/forms/Field';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { useFieldOptions } from './useFieldOptions';

interface TextOptionsProps {
  field: Resource;
}

export function TextOptions({ field }: TextOptionsProps): JSX.Element {
  const [options, setOptions] = useFieldOptions(field);
  const placeholder = (options.placeholder as string | undefined) ?? '';

  return (
    <Field label='Placeholder'>
      <InputWrapper>
        <InputStyled
          value={placeholder}
          onChange={e =>
            setOptions({ ...options, placeholder: e.target.value })
          }
        />
      </InputWrapper>
    </Field>
  );
}
