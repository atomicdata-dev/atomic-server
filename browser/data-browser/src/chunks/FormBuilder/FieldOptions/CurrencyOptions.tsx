import { Resource } from '@tomic/react';
import type { JSX } from 'react';
import Field from '@components/forms/Field';
import { BasicSelect } from '@components/forms/BasicSelect';
import { useFieldOptions } from './useFieldOptions';
import { FieldPair } from './FieldPair';
import { BoundField } from './BoundField';
import { Divider } from './Divider';
import { useFieldConstraint } from '../formDataClass';

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
  const constraint = useFieldConstraint(field);

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
      <Divider />
      <FieldPair>
        <BoundField
          label='Min'
          floor={constraint.minimum}
          max={constraint.maximum}
          optionKey='minimum'
          options={options}
          setOptions={setOptions}
        />
        <BoundField
          label='Max'
          floor={constraint.minimum}
          max={constraint.maximum}
          optionKey='maximum'
          options={options}
          setOptions={setOptions}
        />
      </FieldPair>
    </>
  );
}
