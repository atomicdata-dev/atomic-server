import type { JSX } from 'react';
import type { FieldBlock } from './types.js';

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
      return (
        <input
          id={inputId}
          className='atomic-form-input'
          type={field.type === 'email' ? 'email' : 'text'}
          placeholder={placeholder}
          value={(value as string) ?? ''}
          onChange={e => onChange(e.target.value)}
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

    default:
      return <></>;
  }
}
