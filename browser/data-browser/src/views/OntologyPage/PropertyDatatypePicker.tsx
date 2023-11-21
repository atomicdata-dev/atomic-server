import { Resource, reverseDatatypeMapping, urls } from '@tomic/react';
import { AtomicSelectInput } from '../../components/forms/AtomicSelectInput';
interface PropertyDatatypePickerProps {
  resource: Resource;
  disabled?: boolean;
}

const options = Object.entries(reverseDatatypeMapping)
  .map(([key, value]) => ({
    value: key,
    label: value.toUpperCase(),
  }))
  .filter(x => x.value !== 'unknown-datatype');

export function PropertyDatatypePicker({
  resource,
  disabled,
}: PropertyDatatypePickerProps): JSX.Element {
  return (
    <AtomicSelectInput
      commit
      disabled={disabled}
      resource={resource}
      property={urls.properties.datatype}
      options={options}
    />
  );
}
