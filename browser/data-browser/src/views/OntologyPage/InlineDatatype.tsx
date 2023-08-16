import React from 'react';
import {
  Resource,
  useString,
  urls,
  reverseDatatypeMapping,
  unknownSubject,
} from '@tomic/react';
import { ResourceInline } from '../ResourceInline';
import styled from 'styled-components';

interface TypeSuffixProps {
  resource: Resource;
}

export function InlineDatatype({
  resource,
}: TypeSuffixProps): JSX.Element | null {
  const [datatype] = useString(resource, urls.properties.datatype);
  const [classType] = useString(resource, urls.properties.classType);

  const name = reverseDatatypeMapping[datatype ?? unknownSubject];

  if (!classType) {
    return <span>{name}</span>;
  }

  return (
    <span>
      {name}
      {'<'}
      <ResourceInline subject={classType} />
      {'>'}
    </span>
  );
}
