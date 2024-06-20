import { Resource, core, useCollection } from '@tomic/react';

import { PropertyUsage } from './PropertyUsage';
import { UsageCard } from './UsageCard';
import { ClassUsage } from './ClassUsage';
import { ChildrenUsage } from './ChildrenUsage';
import { Column } from '../Row';

interface ResourceUsageProps {
  resource: Resource;
}

export function ResourceUsage({ resource }: ResourceUsageProps): JSX.Element {
  if (resource.hasClasses(core.classes.property)) {
    return <PropertyUsage resource={resource} />;
  }

  if (resource.hasClasses(core.classes.class)) {
    return <ClassUsage resource={resource} />;
  }

  return <BasicUsage resource={resource} />;
}

function BasicUsage({ resource }: ResourceUsageProps): JSX.Element {
  const { collection } = useCollection({
    value: resource.subject,
  });

  return (
    <Column>
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
    </Column>
  );
}
