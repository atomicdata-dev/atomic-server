import { Link } from 'react-router-dom';
import { useResource } from '@tomic/react';
import { ProgramView, Program } from 'vihreat-lib';

interface ViewProgramProps {
  subject: string;
}

export function ViewProgram({ subject }: ViewProgramProps): JSX.Element {
  const resource = useResource<Program>(subject);

  if (resource === undefined) {
    <p>Failed to load resource {subject}. Is the server running?</p>;
  }

  return (
    <>
      <Link to='/ohjelmat'><strong>←</strong>&nbsp;&nbsp;Ohjelmat</Link>
      <ProgramView resource={resource} />
    </>
  );
}

export default ViewProgram;
