import { Datatype, Property, server } from '@tomic/react';
import { type JSX } from 'react';
import { ResourceSelector } from '@components/forms/ResourceSelector';
import { BasicSelect } from '@components/forms/BasicSelect';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { TagOption } from './RowActionDialog';
import { canonicalJson } from './canonicalJson';

interface TableFilterValueInputProps {
  property: Property;
  value: string;
  onChange: (value: string) => void;
  autoFocus?: boolean;
}

/**
 * Datatype-aware editor for a single filter value. References and resource
 * arrays use the resource search box; everything else gets a fitting plain
 * input. The value is always serialised to a string (matching the query
 * param + `contains_value`'s string comparison).
 */
export function TableFilterValueInput({
  property,
  value,
  onChange,
  autoFocus,
}: TableFilterValueInputProps): JSX.Element {
  const datatype = property.datatype;

  // A select column only holds its own options, so offer exactly those rather
  // than a search over every tag in the drive.
  if (property.allowsOnly?.length) {
    return (
      <BasicSelect
        value={value}
        autoFocus={autoFocus}
        onChange={e => onChange(e.target.value)}
      >
        <option value=''>Pick an option…</option>
        {property.allowsOnly.map(tag => (
          <TagOption key={tag} subject={tag} />
        ))}
      </BasicSelect>
    );
  }

  if (datatype === Datatype.ATOMIC_URL || datatype === Datatype.RESOURCEARRAY) {
    return (
      <ResourceSelector
        value={value || undefined}
        isA={
          property.classType === server.classes.file
            ? undefined
            : property.classType
        }
        hideCreateOption
        autoFocus={autoFocus}
        setSubject={subject => onChange(subject ?? '')}
      />
    );
  }

  if (datatype === Datatype.BOOLEAN) {
    return (
      <BasicSelect
        value={value}
        autoFocus={autoFocus}
        onChange={e => onChange(e.target.value)}
      >
        <option value=''>Any</option>
        <option value='true'>True</option>
        <option value='false'>False</option>
      </BasicSelect>
    );
  }

  const inputType =
    datatype === Datatype.INTEGER || datatype === Datatype.FLOAT
      ? 'number'
      : datatype === Datatype.DATE
        ? 'date'
        : 'text';

  return (
    <InputWrapper>
      <InputStyled
        type={inputType}
        value={value}
        autoFocus={autoFocus}
        placeholder='Value…'
        onChange={e => onChange(e.target.value)}
        onBlur={() => {
          // A JSON value is indexed with its keys sorted and no whitespace, so
          // `{"b":2,"a":1}` would match nothing though a row stores exactly that.
          if (datatype === Datatype.JSON && value !== '') {
            const canonical = canonicalJson(value);

            if (canonical !== undefined && canonical !== value) {
              onChange(canonical);
            }
          }

          // The index compares the text of a stored number, so "2.5e-5" and
          // "0.00002500" would match nothing though they equal a stored 0.000025.
          if (inputType === 'number' && value !== '') {
            const number = Number(value);

            if (Number.isFinite(number) && String(number) !== value) {
              onChange(String(number));
            }
          }
        }}
      />
    </InputWrapper>
  );
}
