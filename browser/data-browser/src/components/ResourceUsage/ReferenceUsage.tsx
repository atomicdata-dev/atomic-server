import { useCollection, type Resource } from '@tomic/react';
import { UsageCard } from './UsageCard';

interface ReferenceUsageProps {
  resource: Resource;
  initialOpenState?: boolean;
}

export function ReferenceUsage({
  resource,
  initialOpenState,
}: ReferenceUsageProps) {
  const { collection } = useCollection({ value: resource.subject });

  return (
    <UsageCard
      initialOpenState={initialOpenState}
      collection={collection}
      title={
        <span>
          <strong>{collection.totalMembers}</strong> resources reference{' '}
          {resource.title}
        </span>
      }
    />
  );
}
