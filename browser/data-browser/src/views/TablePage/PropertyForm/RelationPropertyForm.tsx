import { Datatype, core, useString } from '@tomic/react';
import { useEffect } from 'react';
import { styled } from 'styled-components';
import { ResourceSelector } from '../../../components/forms/ResourceSelector';
import { PropertyCategoryFormProps } from './PropertyCategoryFormProps';
import { Checkbox, CheckboxLabel } from '../../../components/forms/Checkbox';

const valueOpts = { commit: false };

const RELATION_TYPES = new Set<string>([
  Datatype.RESOURCEARRAY,
  Datatype.ATOMIC_URL,
]);

export function RelationPropertyForm({
  resource,
}: PropertyCategoryFormProps): JSX.Element {
  const [classType, setClassType] = useString(
    resource,
    core.properties.classtype,
    valueOpts,
  );

  const [datatype, setDatatype] = useString(resource, core.properties.datatype);

  const handleAllowMultiple = (checked: boolean) => {
    if (checked) {
      setDatatype(Datatype.RESOURCEARRAY);
    } else {
      setDatatype(Datatype.ATOMIC_URL);
    }
  };

  useEffect(() => {
    if (!RELATION_TYPES.has(resource.props.datatype)) {
      setDatatype(Datatype.ATOMIC_URL);
    }
  }, [setDatatype]);

  return (
    <>
      <Label as='label'>
        <strong>Resource type:</strong>
        <ResourceSelector
          isA={core.classes.class}
          value={classType}
          setSubject={setClassType}
        />
      </Label>
      <CheckboxLabel>
        <Checkbox
          onChange={handleAllowMultiple}
          checked={datatype === Datatype.RESOURCEARRAY}
        />
        Allow multiple values
      </CheckboxLabel>
    </>
  );
}

const Label = styled.label`
  display: flex;
  /* align-items: center; */

  flex-direction: column;
  gap: 0.5rem;
  cursor: pointer;
`;
