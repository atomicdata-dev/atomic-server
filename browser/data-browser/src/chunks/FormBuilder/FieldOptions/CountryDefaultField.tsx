import { Resource } from '@tomic/react';
import { useMemo, type JSX } from 'react';
import { countryOptions } from '@tomic/form-renderer';
import Field from '@components/forms/Field';
import { ComboBox, type ComboBoxOption } from '@components/ComboBox';
import { useLocale } from '@components/LocaleContext';
import { useFieldOptions } from './useFieldOptions';

/** The combobox needs a value for "nothing picked"; the options bag stores
 * that as the absence of `defaultCountry`. */
const NO_DEFAULT = '';

interface CountryDefaultFieldProps {
  field: Resource;
  helper: string;
}

/**
 * Picks the `defaultCountry` option — an ISO 3166-1 alpha-2 code — for the
 * question types that start out on a country: `phone` (which country the
 * number selector opens on) and `country` (which option is pre-selected).
 *
 * A searchable ComboBox rather than a plain select: 249 options is more than
 * a dropdown can reasonably be scrolled through, and the names come from
 * `Intl.DisplayNames` in the builder's own locale, so they read the way the
 * editor expects.
 */
export function CountryDefaultField({
  field,
  helper,
}: CountryDefaultFieldProps): JSX.Element {
  const [options, setOptions] = useFieldOptions(field);
  const { locale } = useLocale();

  const selected = (options.defaultCountry as string | undefined) ?? NO_DEFAULT;

  const countries: ComboBoxOption[] = useMemo(
    () => [
      { value: NO_DEFAULT, label: 'No default', searchLabel: 'No default' },
      ...countryOptions(locale).map(({ code, name }) => ({
        value: code,
        label: name,
        searchLabel: `${name} ${code}`,
        prefix: code,
      })),
    ],
    [locale],
  );

  const handleSelect = (value: string | undefined) => {
    const next = { ...options };

    if (!value) {
      delete next.defaultCountry;
    } else {
      next.defaultCountry = value;
    }

    setOptions(next);
  };

  return (
    <Field label='Default country' helper={helper}>
      <ComboBox
        options={countries}
        selectedItem={selected}
        onSelect={handleSelect}
      />
    </Field>
  );
}
