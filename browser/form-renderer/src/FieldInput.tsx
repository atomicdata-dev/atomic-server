import { lazy, Suspense, useState, type JSX } from 'react';
import { CountrySelect } from './CountrySelect.js';
import { MultiSelect, SingleSelect } from './SelectMenu.js';
import {
  ADDRESS_FIELDS,
  type AddressValue,
  type FieldBlock,
  type FieldOptions,
} from './types.js';
import {
  likertScale,
  matrixColumns,
  ratingMax,
  tableColumns,
} from './validation.js';

/** Converts an epoch-ms timestamp to/from the value shape `<input
 * type="datetime-local">` expects (a local, timezone-less string). */
function msToDatetimeLocal(ms: unknown): string {
  if (typeof ms !== 'number') return '';

  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, '0');

  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function datetimeLocalToMs(value: string): number | undefined {
  if (!value) return undefined;

  const ms = new Date(value).getTime();

  return Number.isNaN(ms) ? undefined : ms;
}

/** Symbols for the currencies a form is likely to use; anything else falls
 * back to showing the code itself. */
const CURRENCY_SYMBOLS: Record<string, string> = {
  EUR: '€',
  USD: '$',
  GBP: '£',
  JPY: '¥',
  CNY: '¥',
  INR: '₹',
  BRL: 'R$',
  CHF: 'CHF',
  SEK: 'kr',
  NOK: 'kr',
  DKK: 'kr',
  PLN: 'zł',
  CAD: 'C$',
  AUD: 'A$',
};

function currencySymbol(options: FieldOptions): string {
  const code = (options.currency ?? 'EUR').toUpperCase();

  return CURRENCY_SYMBOLS[code] ?? code;
}

const RATING_GLYPHS: Record<string, { filled: string; empty: string }> = {
  star: { filled: '★', empty: '☆' },
  heart: { filled: '♥', empty: '♡' },
};

interface FieldInputProps {
  field: FieldBlock;
  value: unknown;
  onChange: (value: unknown) => void;
  inputId: string;
  /** id of the associated `<label>` — distinct from `inputId` (see
   * FormRenderer.tsx) — used for `aria-labelledby` on radio/multi-select
   * groups, which have no single input to `htmlFor`. */
  labelId: string;
}

export function FieldInput({
  field,
  value,
  onChange,
  inputId,
  labelId,
}: FieldInputProps): JSX.Element {
  const placeholder = field.options.placeholder;

  switch (field.type) {
    case 'short-text':
    case 'email':
    case 'url':
      return (
        <input
          id={inputId}
          className='atomic-form-input'
          type={TEXTUAL_INPUT_TYPES[field.type]}
          placeholder={placeholder}
          value={(value as string) ?? ''}
          onChange={e => onChange(e.target.value)}
        />
      );
    case 'phone':
      return (
        <Suspense fallback={<PhoneFieldFallback inputId={inputId} />}>
          <PhoneField
            inputId={inputId}
            placeholder={placeholder}
            defaultCountry={field.options.defaultCountry}
            value={value}
            onChange={onChange}
          />
        </Suspense>
      );
    case 'country':
      return (
        <CountrySelect
          id={inputId}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          defaultCode={field.options.defaultCountry}
        />
      );
    case 'long-text':
      return (
        <textarea
          id={inputId}
          className='atomic-form-input atomic-form-textarea'
          placeholder={placeholder}
          value={(value as string) ?? ''}
          onChange={e => onChange(e.target.value)}
          rows={4}
        />
      );
    case 'number':
      return (
        <input
          id={inputId}
          className='atomic-form-input'
          type='number'
          placeholder={placeholder}
          min={field.options.min}
          max={field.options.max}
          value={(value as number | string) ?? ''}
          onChange={e =>
            onChange(e.target.value === '' ? undefined : Number(e.target.value))
          }
        />
      );
    case 'currency':
      return (
        // A `<label>` rather than a `<div>`: the symbol now sits inside the
        // bordered box, so clicking it — or the padding around it — should
        // put the cursor in the number, the way it would anywhere else in an
        // input. The symbol is `aria-hidden`, so this second label adds
        // nothing to the field's accessible name.
        <label className='atomic-form-currency' htmlFor={inputId}>
          <span className='atomic-form-currency-symbol' aria-hidden='true'>
            {currencySymbol(field.options)}
          </span>
          <input
            id={inputId}
            className='atomic-form-input'
            type='number'
            step='0.01'
            placeholder={placeholder}
            min={field.options.min}
            max={field.options.max}
            value={(value as number | string) ?? ''}
            onChange={e =>
              onChange(
                e.target.value === '' ? undefined : Number(e.target.value),
              )
            }
          />
        </label>
      );
    case 'date':
      return (
        <input
          id={inputId}
          className='atomic-form-input'
          type='date'
          value={(value as string) ?? ''}
          onChange={e => onChange(e.target.value || undefined)}
        />
      );
    case 'datetime':
      return (
        <input
          id={inputId}
          className='atomic-form-input'
          type='datetime-local'
          value={msToDatetimeLocal(value)}
          onChange={e => onChange(datetimeLocalToMs(e.target.value))}
        />
      );
    case 'checkbox':
      return (
        <label className='atomic-form-checkbox-row'>
          <input
            id={inputId}
            type='checkbox'
            checked={Boolean(value)}
            onChange={e => onChange(e.target.checked)}
          />
          <span>{field.label}</span>
        </label>
      );
    case 'radio':
      return (
        <div
          className='atomic-form-choice-group'
          role='radiogroup'
          aria-labelledby={labelId}
        >
          {(field.options.options ?? []).map(option => (
            <label className='atomic-form-choice-row' key={option}>
              <input
                type='radio'
                name={inputId}
                checked={value === option}
                onChange={() => onChange(option)}
              />
              <span>{option}</span>
            </label>
          ))}
        </div>
      );

    case 'multi-select': {
      const selected = Array.isArray(value) ? (value as string[]) : [];

      return (
        <div className='atomic-form-choice-group' aria-labelledby={labelId}>
          {(field.options.options ?? []).map(option => (
            <label className='atomic-form-choice-row' key={option}>
              <input
                type='checkbox'
                checked={selected.includes(option)}
                onChange={e =>
                  onChange(
                    e.target.checked
                      ? [...selected, option]
                      : selected.filter(o => o !== option),
                  )
                }
              />
              <span>{option}</span>
            </label>
          ))}
        </div>
      );
    }

    case 'dropdown':
      return (
        <SingleSelect
          options={field.options.options ?? []}
          value={typeof value === 'string' ? value : undefined}
          onChange={onChange}
          inputId={inputId}
          labelId={labelId}
          placeholder={placeholder}
        />
      );

    case 'dropdown-multi':
      return (
        <MultiSelect
          options={field.options.options ?? []}
          value={Array.isArray(value) ? (value as string[]) : []}
          onChange={onChange}
          inputId={inputId}
          labelId={labelId}
          placeholder={placeholder}
        />
      );

    case 'likert': {
      const scale = likertScale(field.options);

      return (
        <div
          className='atomic-form-likert'
          role='radiogroup'
          aria-labelledby={labelId}
        >
          {field.options.minLabel && (
            <span className='atomic-form-likert-end'>
              {field.options.minLabel}
            </span>
          )}
          <div className='atomic-form-likert-scale'>
            {Array.from({ length: scale }, (_, i) => i + 1).map(step => (
              <label className='atomic-form-likert-step' key={step}>
                <input
                  type='radio'
                  name={inputId}
                  checked={value === step}
                  onChange={() => onChange(step)}
                />
                <span>{step}</span>
              </label>
            ))}
          </div>
          {field.options.maxLabel && (
            <span className='atomic-form-likert-end'>
              {field.options.maxLabel}
            </span>
          )}
        </div>
      );
    }

    case 'rating':
      return (
        <RatingField
          field={field}
          value={value}
          onChange={onChange}
          inputId={inputId}
          labelId={labelId}
        />
      );

    case 'picture-choice': {
      const options = field.options.options ?? [];
      const images = field.options.optionImages ?? [];

      return (
        <div
          className='atomic-form-picture-group'
          role='radiogroup'
          aria-labelledby={labelId}
        >
          {options.map((option, index) => (
            <label
              className={`atomic-form-picture-card${value === option ? ' atomic-form-picture-card-selected' : ''}`}
              key={option}
            >
              <input
                type='radio'
                name={inputId}
                checked={value === option}
                onChange={() => onChange(option)}
              />
              {images[index] ? (
                <img src={images[index] as string} alt='' loading='lazy' />
              ) : (
                <span className='atomic-form-picture-placeholder' />
              )}
              <span className='atomic-form-picture-label'>{option}</span>
            </label>
          ))}
        </div>
      );
    }

    case 'choice-matrix': {
      const rows = field.options.rows ?? [];
      const columns = matrixColumns(field.options);
      const answers = isPlainObject(value) ? value : {};

      return (
        <div className='atomic-form-matrix-wrapper'>
          <table className='atomic-form-matrix' aria-labelledby={labelId}>
            <thead>
              <tr>
                <td />
                {columns.map(column => (
                  <th scope='col' key={column}>
                    {column}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map(row => (
                <tr key={row}>
                  <th scope='row'>{row}</th>
                  {columns.map(column => (
                    <td key={column}>
                      <label
                        className='atomic-form-matrix-cell'
                        title={`${row}: ${column}`}
                      >
                        <input
                          type='radio'
                          name={`${inputId}-${row}`}
                          checked={answers[row] === column}
                          onChange={() =>
                            onChange({ ...answers, [row]: column })
                          }
                        />
                        <span className='atomic-form-visually-hidden'>
                          {`${row}: ${column}`}
                        </span>
                      </label>
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    }

    case 'table-input': {
      const columns = tableColumns(field.options);
      const stored = Array.isArray(value)
        ? (value as Record<string, unknown>[])
        : [];
      // Always show at least `minRows` (or one) editable rows, even before
      // the visitor has typed anything — an empty grid has nothing to click.
      const minRows = Math.max(field.options.minRows ?? 1, 1);
      const rows: Record<string, unknown>[] =
        stored.length >= minRows
          ? stored
          : [
              ...stored,
              ...Array.from(
                { length: minRows - stored.length },
                (): Record<string, unknown> => ({}),
              ),
            ];
      const canAddRow =
        field.options.maxRows === undefined ||
        rows.length < field.options.maxRows;

      const update = (next: Record<string, unknown>[]) => onChange(next);

      return (
        <div className='atomic-form-matrix-wrapper'>
          <table className='atomic-form-table-input' aria-labelledby={labelId}>
            <thead>
              <tr>
                {columns.map(column => (
                  <th scope='col' key={column.label}>
                    {column.label}
                  </th>
                ))}
                <td />
              </tr>
            </thead>
            <tbody>
              {rows.map((row, rowIndex) => (
                <tr key={`row-${rowIndex}`}>
                  {columns.map(column => (
                    <td key={column.label}>
                      <input
                        className='atomic-form-input'
                        type={column.type === 'number' ? 'number' : 'text'}
                        aria-label={`${column.label}, row ${rowIndex + 1}`}
                        value={(row[column.label] as string | number) ?? ''}
                        onChange={e => {
                          const raw = e.target.value;
                          const next = rows.map((r, i) =>
                            i === rowIndex
                              ? {
                                  ...r,
                                  [column.label]:
                                    column.type === 'number'
                                      ? raw === ''
                                        ? undefined
                                        : Number(raw)
                                      : raw,
                                }
                              : r,
                          );
                          update(next);
                        }}
                      />
                    </td>
                  ))}
                  <td>
                    {rows.length > minRows && (
                      <button
                        type='button'
                        className='atomic-form-row-button'
                        title='Remove row'
                        onClick={() =>
                          update(rows.filter((_, i) => i !== rowIndex))
                        }
                      >
                        ×
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {canAddRow && (
            <button
              type='button'
              className='atomic-form-button atomic-form-button-secondary atomic-form-add-row'
              onClick={() => onChange([...rows, {}])}
            >
              Add row
            </button>
          )}
        </div>
      );
    }

    case 'address': {
      const address: AddressValue = isPlainObject(value)
        ? (value as AddressValue)
        : {};

      return (
        <div className='atomic-form-address' aria-labelledby={labelId}>
          {ADDRESS_FIELDS.map(({ key, label, autoComplete }) => (
            <label className='atomic-form-address-field' key={key}>
              <span className='atomic-form-address-label'>{label}</span>
              {key === 'country' ? (
                <CountrySelect
                  value={address.country}
                  onChange={code => onChange({ ...address, country: code })}
                />
              ) : (
                <input
                  className='atomic-form-input'
                  type='text'
                  autoComplete={autoComplete}
                  value={address[key] ?? ''}
                  onChange={e =>
                    onChange({ ...address, [key]: e.target.value })
                  }
                />
              )}
            </label>
          ))}
        </div>
      );
    }

    default:
      return <></>;
  }
}

/** Star/heart rating. Hovering a step previews that score by filling every
 * glyph up to the pointer — the behaviour a rating widget is expected to
 * have, and the reason this one needs state of its own instead of living in
 * `FieldInput`'s switch. */
function RatingField({
  field,
  value,
  onChange,
  inputId,
  labelId,
}: FieldInputProps): JSX.Element {
  const [hovered, setHovered] = useState<number | undefined>(undefined);
  const max = ratingMax(field.options);
  const glyphs =
    RATING_GLYPHS[field.options.icon ?? 'star'] ?? RATING_GLYPHS.star;
  const current = typeof value === 'number' ? value : 0;
  // While hovering, the preview stands in for the stored value.
  const shown = hovered ?? current;

  return (
    // Enter is tracked per glyph and leave on a plain `fit-content` wrapper —
    // one handler for the whole scale, so crossing the gap between two glyphs
    // can't blank the preview for a frame. Neither element carries a role:
    // mouse handlers on a non-interactive role (the radiogroup, a label) are
    // an a11y lint error.
    <div
      className='atomic-form-rating'
      onMouseLeave={() => setHovered(undefined)}
    >
      <div
        className='atomic-form-rating-scale'
        role='radiogroup'
        aria-labelledby={labelId}
      >
        {Array.from({ length: max }, (_, i) => i + 1).map(step => (
          <label
            className={`atomic-form-rating-step${
              hovered !== undefined && step <= hovered
                ? ' atomic-form-rating-step-hot'
                : ''
            }`}
            key={step}
            title={`${step} / ${max}`}
          >
            <input
              type='radio'
              name={inputId}
              aria-label={`${step} out of ${max}`}
              checked={current === step}
              onChange={() => onChange(step)}
            />
            <span aria-hidden='true' onMouseEnter={() => setHovered(step)}>
              {step <= shown ? glyphs.filled : glyphs.empty}
            </span>
          </label>
        ))}
      </div>
    </div>
  );
}

/** `react-phone-number-input` + its flag icons dwarf the rest of this
 * package, so the phone input is a chunk of its own, fetched only by forms
 * that actually ask for a phone number. */
const PhoneField = lazy(() => import('./PhoneField.js'));

/** Holds the phone field's space (and its label association) for the tick or
 * two the chunk takes to arrive. */
function PhoneFieldFallback({ inputId }: { inputId: string }): JSX.Element {
  return <input id={inputId} className='atomic-form-input' disabled />;
}

const TEXTUAL_INPUT_TYPES: Record<string, string> = {
  'short-text': 'text',
  email: 'email',
  url: 'url',
};

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
