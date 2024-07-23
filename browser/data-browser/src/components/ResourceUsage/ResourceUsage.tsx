import { Resource, core } from '@tomic/react';

import { PropertyUsage } from './PropertyUsage';
import { ClassUsage } from './ClassUsage';
import { ChildrenUsage } from './ChildrenUsage';
import { Column } from '../Row';
import { ReferenceUsage } from './ReferenceUsage';

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
  return (
    <Column>
      <ChildrenUsage resource={resource} />
      <ReferenceUsage resource={resource} />
    </Column>
  );
}
