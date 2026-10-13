import { useResource, core, server, useTitle } from '@tomic/react';
import { formatPlainValue } from '@helpers/formatPlainValue';
import { ResourceCellProps } from '../Type';
import { AgentCell } from './AgentCell';
import { FileCell } from './FileCell';
import { SimpleResourceLink } from './SimpleResourceLink';

export function ResourceCell({ subject }: ResourceCellProps) {
  // The value is whatever the row stores, so it can be an object or a number
  // where a link is expected. `useResource` throws for those, which took the
  // whole table down through its error boundary. Show the plain value instead.
  if (typeof subject !== 'string') {
    return <>{formatPlainValue(subject)}</>;
  }

  return <ResolvedResourceCell subject={subject} />;
}

function ResolvedResourceCell({ subject }: ResourceCellProps) {
  const resource = useResource(subject);

  const Comp = resource.matchClass(
    {
      [core.classes.agent]: AgentCell,
      [server.classes.file]: FileCell,
    },
    BasicCell,
  );

  return <Comp subject={subject} />;
}

function BasicCell({ subject }: ResourceCellProps) {
  const resource = useResource(subject);
  const [title] = useTitle(resource);

  return <SimpleResourceLink resource={resource}>{title}</SimpleResourceLink>;
}
