import { forms, Resource, useValue, type JSONValue } from '@tomic/react';
import type { JSX } from 'react';
import Field from '@components/forms/Field';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { Row } from '@components/Row';

interface NumberOptionsProps {
  field: Resource;
}

export function NumberOptions({ field }: NumberOptionsProps): JSX.Element {
  const [options, setOptions] = useValue(
    field,
    forms.properties.formFieldOptions,
    { commit: true },
  );

  const opts = (options as Record<string, JSONValue> | undefined) ?? {};
  const placeholder = (opts.placeholder as string | undefined) ?? '';
  const min = opts.min as number | undefined;
  const max = opts.max as number | undefined;

  const setBound = (key: 'min' | 'max', value: string) => {
    const next = { ...opts };

    if (value.trim() === '') {
      delete next[key];
    } else {
      next[key] = Number(value);
    }

    setOptions(next);
  };

  return (
    <>
      <Row gap="0.5rem" wrapItems>
        <Field label="Min">
          <InputWrapper>
            <InputStyled
              type="number"
              value={min ?? ''}
              onChange={e => setBound('min', e.target.value)}
            />
          </InputWrapper>
        </Field>
        <Field label="Max">
          <InputWrapper>
            <InputStyled
              type="number"
              value={max ?? ''}
              onChange={e => setBound('max', e.target.value)}
            />
          </InputWrapper>
        </Field>
      </Row>
      <Field label="Placeholder">
        <InputWrapper>
          <InputStyled
            value={placeholder}
            onChange={e => setOptions({ ...opts, placeholder: e.target.value })}
          />
        </InputWrapper>
      </Field>
    </>
  );
}
