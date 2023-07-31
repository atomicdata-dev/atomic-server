import { urls, useStore, useString } from '@tomic/react';
import React, { useEffect, useState } from 'react';
import styled from 'styled-components';
import { ResourceSelector } from '../../../components/forms/ResourceSelector';
import { PropertyCategoryFormProps } from './PropertyCategoryFormProps';

const valueOpts = { commit: false };

export function RelationPropertyForm({
  resource,
}: PropertyCategoryFormProps): JSX.Element {
  const store = useStore();
  const [classType, setClassType] = useString(
    resource,
    urls.properties.classType,
    valueOpts,
  );

  const [error, setError] = useState<Error>();

  useEffect(() => {
    resource.set(urls.properties.datatype, urls.datatypes.atomicUrl, store);
  }, []);

  return (
    <>
      <Label as='label'>
        <strong>Resource type:</strong>
        <ResourceSelector
          classType={urls.classes.class}
          value={classType}
          setSubject={setClassType}
          onValidate={setError}
        />
      </Label>
      {error}
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
