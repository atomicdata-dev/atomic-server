import { Resource, useCollection, properties } from '@tomic/react';

import { UsageCard } from './UsageCard';
import { Column } from '../Row';
import { ChildrenUsage } from './ChildrenUsage';

interface ClassUsageProps {
  resource: Resource;
}

export function ClassUsage({ resource }: ClassUsageProps): JSX.Element {
  const { collection: instanceOfClassCollection } = useCollection({
    property: properties.isA,
    value: resource.getSubject(),
  });

  const { collection: classTypeCollection } = useCollection({
    property: properties.classType,
    value: resource.getSubject(),
  });

  const instanceTotal = instanceOfClassCollection.totalMembers;
  const classTypeTotal = classTypeCollection.totalMembers;
  const totalUsage = instanceTotal + classTypeTotal;

  return (
    <Column>
      <ChildrenUsage resource={resource} />
      {totalUsage === 0 && 'No usage of class found.'}
      {instanceTotal > 0 && (
        <UsageCard
          collection={instanceOfClassCollection}
          title={
            <span>
              <strong>{instanceTotal}</strong> resources are an instance of{' '}
              {resource.title}
            </span>
          }
        />
      )}
      {classTypeTotal > 0 && (
        <UsageCard
          collection={classTypeCollection}
          title={
            <span>
              <strong>{classTypeTotal}</strong> properties have {resource.title}{' '}
              as a classtype.
            </span>
          }
        />
      )}
    </Column>
  );
}
