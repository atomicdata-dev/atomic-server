import { Resource, reverseDatatypeMapping, urls, useArray } from '@tomic/react';
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
  const [_, setAllowsOnly] = useArray(resource, urls.properties.allowsOnly, {
    commit: true,
  });

  const removeAllowsOnlyForNonResourceArray = (type: string) => {
    if (type === urls.datatypes.resourceArray) {
      return;
    }

    setAllowsOnly(undefined);
  };

  return (
    <AtomicSelectInput
      commit
      disabled={disabled}
      resource={resource}
      property={urls.properties.datatype}
      options={options}
      onChange={removeAllowsOnlyForNonResourceArray}
    />
  );
}
