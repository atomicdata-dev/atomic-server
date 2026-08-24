import { Resource } from '@tomic/react';
import type { JSX } from 'react';
import Field from '@components/forms/Field';
import { BasicSelect } from '@components/forms/BasicSelect';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { Row } from '@components/Row';
import { useFieldOptions } from './useFieldOptions';

/** Currencies the renderer knows a symbol for (`CURRENCY_SYMBOLS` in
 * `@tomic/form-renderer`'s FieldInput); anything else renders as its code. */
const CURRENCIES = [
  'EUR',
  'USD',
  'GBP',
  'CHF',
  'SEK',
  'NOK',
  'DKK',
  'PLN',
  'CAD',
  'AUD',
  'JPY',
  'CNY',
  'INR',
  'BRL',
];

interface CurrencyOptionsProps {
  field: Resource;
}

export function CurrencyOptions({ field }: CurrencyOptionsProps): JSX.Element {
  const [options, setOptions] = useFieldOptions(field);

  const currency = (options.currency as string | undefined) ?? 'EUR';
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
      <Field label='Currency'>
        <BasicSelect
          value={currency}
          onChange={e => setOptions({ ...options, currency: e.target.value })}
        >
          {CURRENCIES.map(code => (
            <option key={code} value={code}>
              {code}
            </option>
          ))}
        </BasicSelect>
      </Field>
      <Row gap='0.5rem' wrapItems>
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
      </Row>
    </>
  );
}
