import {
  Datatype,
  Resource,
  reverseDatatypeMapping,
  core,
  useArray,
  useStore,
  useString,
} from '@tomic/react';
import { AtomicSelectInput } from '../../components/forms/AtomicSelectInput';
import { BasicSelect } from '../../components/forms/BasicSelect';
import {
  createPropertyDraft,
  isContentAddressed,
  recreatePropertyWithDatatype,
} from '../../helpers/propertyIdentity';
import toast from 'react-hot-toast';
import styled from 'styled-components';
import type { JSX } from 'react';
interface PropertyDatatypePickerProps {
  resource: Resource;
  disabled?: boolean;
}

export const datatypeOptions = Object.entries(reverseDatatypeMapping)
  .map(([key, value]) => ({
    value: key,
    label: value.toUpperCase(),
  }))
  .filter(x => x.value !== 'unknown-datatype');

const isResourceLike = (datatype: string) => {
  return (
    datatype === Datatype.ATOMIC_URL || datatype === Datatype.RESOURCEARRAY
  );
};

export function PropertyDatatypePicker(
  props: PropertyDatatypePickerProps,
): JSX.Element {
  return isContentAddressed(props.resource.subject) ? (
    <ContentAddressedDatatypePicker {...props} />
  ) : (
    <LegacyDatatypePicker {...props} />
  );
}

/**
 * The datatype is part of a content-addressed property's ID, so changing it
 * creates a new property (same parent and shortname) and swaps it into the
 * classes and ontology that listed the old one.
 */
function ContentAddressedDatatypePicker({
  resource,
  disabled,
}: PropertyDatatypePickerProps): JSX.Element {
  const store = useStore();
  const [datatype] = useString(resource, core.properties.datatype);

  const handleChange = async (e: React.ChangeEvent<HTMLSelectElement>) => {
    const newDatatype = e.target.value;

    if (newDatatype === datatype) {
      return;
    }

    try {
      const draft = await createPropertyDraft(
        store,
        resource.get(core.properties.parent) as string,
        { source: resource },
      );
      await draft.set(core.properties.datatype, newDatatype);

      if (!isResourceLike(newDatatype)) {
        draft.remove(core.properties.classtype);
        draft.remove(core.properties.allowsOnly);
      }

      await recreatePropertyWithDatatype(store, resource, draft);
    } catch (err) {
      toast.error(`Could not change datatype: ${(err as Error).message}`);
    }
  };

  return (
    <StyledBasicSelect
      aria-label='Property datatype'
      disabled={disabled}
      value={datatype}
      onChange={handleChange}
    >
      {datatypeOptions.map(option => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      ))}
    </StyledBasicSelect>
  );
}

function LegacyDatatypePicker({
  resource,
  disabled,
}: PropertyDatatypePickerProps): JSX.Element {
  const [, setAllowsOnly] = useArray(resource, core.properties.allowsOnly, {
    commit: true,
  });
  const [, setClassType] = useString(resource, core.properties.classtype, {
    commit: true,
  });

  const clearInapplicableProps = (datatype: string) => {
    if (!isResourceLike(datatype)) {
      setClassType(undefined);
      setAllowsOnly(undefined);
    }
  };

  return (
    <StyledAtomicSelectInput
      aria-label='Property datatype'
      commit
      disabled={disabled}
      resource={resource}
      property={core.properties.datatype}
      options={datatypeOptions}
      onChange={clearInapplicableProps}
    />
  );
}

const StyledAtomicSelectInput = styled(AtomicSelectInput)`
  min-width: 18ch;
`;

const StyledBasicSelect = styled(BasicSelect)`
  min-width: 18ch;
`;
