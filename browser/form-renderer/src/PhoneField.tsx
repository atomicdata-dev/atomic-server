/**
 * The `phone` field's input, in its own module so `FieldInput` can lazy-load
 * it: `react-phone-number-input` plus the inline flag icons is by far the
 * heaviest thing this package pulls in, and most forms have no phone field.
 */
import type { JSX } from 'react';
import PhoneInput, { type Country } from 'react-phone-number-input';
import flags from 'react-phone-number-input/flags';
import { isCountryCode } from './countries.js';

interface PhoneFieldProps {
  value: unknown;
  onChange: (value: unknown) => void;
  inputId: string;
  placeholder?: string;
  /** The field's `defaultCountry` option: which country the selector starts
   * on, so a visitor typing a national number gets it read correctly. */
  defaultCountry?: string;
}

export default function PhoneField({
  value,
  onChange,
  inputId,
  placeholder,
  defaultCountry,
}: PhoneFieldProps): JSX.Element {
  return (
    <PhoneInput
      id={inputId}
      className='atomic-form-phone'
      numberInputProps={{ className: 'atomic-form-input' }}
      international
      /* `Country` is a union of the library's own code literals, so a value
       * out of the form definition has to be checked before it can be one. */
      defaultCountry={
        isCountryCode(defaultCountry) ? (defaultCountry as Country) : undefined
      }
      /* Bundles the icons as inline SVG; the library otherwise fetches them
       * from a third-party CDN at render time. */
      flags={flags}
      placeholder={placeholder}
      /* The component only understands E.164 (`+31612345678`) or nothing —
       * an empty string would make it an uncontrolled input. */
      value={(value as string) || undefined}
      onChange={v => onChange(v ?? undefined)}
    />
  );
}
