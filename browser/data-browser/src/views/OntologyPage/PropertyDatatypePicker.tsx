import {
  Datatype,
  Resource,
  reverseDatatypeMapping,
  core,
  useArray,
  useString,
} from '@tomic/react';
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
  const [, setAllowsOnly] = useArray(resource, core.properties.allowsOnly, {
    commit: true,
  });
  const [, setClassType] = useString(resource, core.properties.classtype, {
    commit: true,
  });

  const isResourceLike = (datatype: string) => {
    return (
      datatype === Datatype.ATOMIC_URL || datatype === Datatype.RESOURCEARRAY
    );
  };

  const clearInapplicableProps = (datatype: string) => {
    if (!isResourceLike(datatype)) {
      setClassType(undefined);
      setAllowsOnly(undefined);
    }
  };

  return (
    <AtomicSelectInput
      commit
      disabled={disabled}
      resource={resource}
      property={core.properties.datatype}
      options={options}
      onChange={clearInapplicableProps}
    />
  );
}
