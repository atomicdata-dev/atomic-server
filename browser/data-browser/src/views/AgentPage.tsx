import * as React from 'react';
import { useArray, useTitle, properties } from '@tomic/react';

import { ContainerNarrow } from '../components/Containers';
import { CardRow } from '../components/Card';
import { ResourceInline } from './ResourceInline';
import { ValueForm } from '../components/forms/ValueForm';
import { ResourcePageProps } from './ResourcePage';

/** A View for Drives, which function similar to a homepage or dashboard. */
function AgentPage({ resource }: ResourcePageProps): JSX.Element {
  const [title] = useTitle(resource);
  const [children] = useArray(resource, properties.children);

  return (
    <ContainerNarrow>
      <ValueForm resource={resource} propertyURL={properties.description} />
      <h1>{title}</h1>
      {children.map(child => {
        return (
          <CardRow key={child}>
            <ResourceInline subject={child} />
          </CardRow>
        );
      })}
    </ContainerNarrow>
  );
}

export default AgentPage;
