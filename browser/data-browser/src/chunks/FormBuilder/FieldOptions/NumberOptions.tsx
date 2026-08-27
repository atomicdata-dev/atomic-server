import { Resource } from '@tomic/react';
import type { JSX } from 'react';
import Field from '@components/forms/Field';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { useFieldOptions } from './useFieldOptions';
import { FieldPair } from './FieldPair';

interface NumberOptionsProps {
  field: Resource;
}

export function NumberOptions({ field }: NumberOptionsProps): JSX.Element {
  const [options, setOptions] = useFieldOptions(field);

  const placeholder = (options.placeholder as string | undefined) ?? '';
  const min = options.min as number | undefined;
  const max = options.max as number | undefined;

  const setBound = (key: 'min' | 'max', value: string) => {
    const next = { ...options };

    if (value.trim() === '') {
      delete next[key];
    } else {
      next[key] = Number(value);
    }

    setOptions(next);
  };

  return (
    <>
      <FieldPair>
        <Field label='Min'>
          <InputWrapper>
            <InputStyled
              type='number'
              value={min ?? ''}
              onChange={e => setBound('min', e.target.value)}
            />
          </InputWrapper>
        </Field>
        <Field label='Max'>
          <InputWrapper>
            <InputStyled
              type='number'
              value={max ?? ''}
              onChange={e => setBound('max', e.target.value)}
            />
          </InputWrapper>
        </Field>
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
