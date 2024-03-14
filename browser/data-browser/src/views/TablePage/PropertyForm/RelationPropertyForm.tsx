import { Datatype, core, useString } from '@tomic/react';
import { useEffect } from 'react';
import { styled } from 'styled-components';
import { ResourceSelector } from '../../../components/forms/ResourceSelector';
import { PropertyCategoryFormProps } from './PropertyCategoryFormProps';

const valueOpts = { commit: false };

export function RelationPropertyForm({
  resource,
}: PropertyCategoryFormProps): JSX.Element {
  const [classType, setClassType] = useString(
    resource,
    core.properties.classtype,
    valueOpts,
  );

  useEffect(() => {
    resource.set(core.properties.datatype, Datatype.ATOMIC_URL);
  }, []);

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
