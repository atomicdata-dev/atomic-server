import { Resource, classes, useCollection } from '@tomic/react';
import React from 'react';
import { PropertyUsage } from './PropertyUsage';
import { UsageCard } from './UsageCard';
import { ClassUsage } from './ClassUsage';
import { ChildrenUsage } from './ChildrenUsage';

interface ResourceUsageProps {
  resource: Resource;
}

export function ResourceUsage({ resource }: ResourceUsageProps): JSX.Element {
  if (resource.hasClasses(classes.property)) {
    return <PropertyUsage resource={resource} />;
  }

  if (resource.hasClasses(classes.class)) {
    return <ClassUsage resource={resource} />;
  }

  return <BasicUsage resource={resource} />;
}

function BasicUsage({ resource }: ResourceUsageProps): JSX.Element {
  const { collection } = useCollection({
    value: resource.getSubject(),
  });

  return (
    <>
      <ChildrenUsage resource={resource} />
      <UsageCard
        collection={collection}
        title={
          <span>
            <strong>{collection.totalMembers}</strong> resources reference{' '}
            {resource.title}
          </span>
        }
      />
    </>
  );
}
