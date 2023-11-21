import { Resource, useCollection, properties } from '@tomic/react';

import { UsageCard } from './UsageCard';
import { Column } from '../Row';
import { ChildrenUsage } from './ChildrenUsage';

interface PropertyUsageProps {
  resource: Resource;
}

export function PropertyUsage({ resource }: PropertyUsageProps): JSX.Element {
  const { collection: instancesWithPropCollection } = useCollection({
    property: resource.getSubject(),
  });

  const { collection: requiresPropCollection } = useCollection({
    property: properties.requires,
    value: resource.getSubject(),
  });

  const { collection: recommendsPropCollection } = useCollection({
    property: properties.recommends,
    value: resource.getSubject(),
  });

  const instanceTotal = instancesWithPropCollection.totalMembers;
  const requiresTotal = requiresPropCollection.totalMembers;
  const recommendsTotal = recommendsPropCollection.totalMembers;

  return (
    <Column>
      <ChildrenUsage resource={resource} />
      {instanceTotal > 0 && (
        <UsageCard
          collection={instancesWithPropCollection}
          title={
            <span>
              <strong>{instanceTotal}</strong> resources have a {resource.title}{' '}
              property
            </span>
          }
        />
      )}
      {requiresTotal > 0 && (
        <UsageCard
          collection={requiresPropCollection}
          title={
            <span>
              <strong>{requiresTotal}</strong> classes require this property
            </span>
          }
        />
      )}
      {recommendsTotal > 0 && (
        <UsageCard
          collection={recommendsPropCollection}
          title={
            <span>
              <strong>{recommendsTotal}</strong> classes recommend this property
            </span>
          }
        />
      )}
    </Column>
  );
}
