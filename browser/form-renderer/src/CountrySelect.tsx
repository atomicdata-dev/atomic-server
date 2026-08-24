import { useEffect, type JSX } from 'react';
import { countryOptions, isCountryCode } from './countries.js';

interface CountrySelectProps {
  value: unknown;
  onChange: (code: string | undefined) => void;
  id?: string;
  /** Label for the empty option — also what the select shows while nothing is
   * picked. */
  placeholder?: string;
  /** The field's configured default, applied once on mount when the visitor
   * has no answer yet. Left unset by the `address` subfield: seeding one
   * corner of a composite would make an otherwise untouched address count as
   * answered. */
  defaultCode?: string;
}

/**
 * A plain `<select>` over [countries.ts]'s list. Native on purpose: it is
 * keyboard-searchable for free, becomes the platform picker on mobile, and
 * costs nothing to ship — this package renders on strangers' forms.
 */
export function CountrySelect({
  value,
  onChange,
  id,
  placeholder,
  defaultCode,
}: CountrySelectProps): JSX.Element {
  const selected = typeof value === 'string' ? value : '';

  useEffect(() => {
    if (!selected && isCountryCode(defaultCode)) {
      onChange(defaultCode);
    }
    // Mount only: re-running this on every change would refill the field the
    // moment the visitor clears it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <select
      id={id}
      className='atomic-form-input atomic-form-select'
      value={selected}
      onChange={e =>
        onChange(e.target.value === '' ? undefined : e.target.value)
      }
    >
      <option value=''>{placeholder ?? 'Select a country'}</option>
      {countryOptions().map(({ code, name }) => (
        <option key={code} value={code}>
          {name}
        </option>
      ))}
      {/* A stored value the list doesn't know (a legacy free-text address
          country, say) still needs to render as the selected option. */}
      {selected && !isCountryCode(selected) && (
        <option value={selected}>{selected}</option>
      )}
    </select>
  );
}
