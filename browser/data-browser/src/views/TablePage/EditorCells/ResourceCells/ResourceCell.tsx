import { useResource, core, server, useTitle } from '@tomic/react';
import { ResourceCellProps } from '../Type';
import { AgentCell } from './AgentCell';
import { FileCell } from './FileCell';
import { SimpleResourceLink } from './SimpleResourceLink';

export function ResourceCell({ subject }: ResourceCellProps) {
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
