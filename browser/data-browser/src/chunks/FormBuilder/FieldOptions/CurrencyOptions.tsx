import { Resource } from '@tomic/react';
import type { JSX } from 'react';
import Field from '@components/forms/Field';
import { BasicSelect } from '@components/forms/BasicSelect';
import { useFieldOptions } from './useFieldOptions';
import { FieldPair } from './FieldPair';
import { BoundField } from './BoundField';

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
    </>
  );
}
