import { useParams } from 'react-router-dom';
import { useResource } from '@tomic/react';
import { ProgramView, Program } from 'vihreat-lib';

export function ViewProgram(): JSX.Element {
  const { id } = useParams();
  const subject = `http://localhost:9883/ohjelmat/${id}`;

  const resource = useResource<Program>(subject);

  if (resource === undefined) {
    <p>Failed to load resource {subject}. Is the server running?</p>;
  }

  return <ProgramView resource={resource} />;
}

export default ViewProgram;
