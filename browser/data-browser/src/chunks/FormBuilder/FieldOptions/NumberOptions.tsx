import { Resource } from '@tomic/react';
import type { JSX } from 'react';
import Field from '@components/forms/Field';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { useFieldOptions } from './useFieldOptions';
import { FieldPair } from './FieldPair';
import { BoundField } from './BoundField';

interface NumberOptionsProps {
  field: Resource;
}

export function NumberOptions({ field }: NumberOptionsProps): JSX.Element {
  const [options, setOptions] = useFieldOptions(field);

  const placeholder = (options.placeholder as string | undefined) ?? '';

  return (
    <>
      <FieldPair>
        <BoundField
          label='Min'
          optionKey='min'
          options={options}
          setOptions={setOptions}
        />
        <BoundField
          label='Max'
          optionKey='max'
          options={options}
          setOptions={setOptions}
        />
      </FieldPair>
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
    </>
  );
}
