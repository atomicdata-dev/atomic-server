import { useString, properties } from '@tomic/react';

import { CommitDetail } from '../../components/CommitDetail';
import Markdown from '../../components/datatypes/Markdown';
import { Detail, Details } from '../../components/Detail';
import { ResourceInline } from '../ResourceInline';
import { ResourcePageProps } from '../ResourcePage';

/** Card Message view that shows parent */
export function MessageCard({ resource }: ResourcePageProps) {
  const [description] = useString(resource, properties.description);
  const [parent] = useString(resource, properties.parent);
  const [lastCommit] = useString(resource, properties.commit.lastCommit);

  return (
    <>
      <Details>
        <Detail>
          Message in <ResourceInline subject={parent!} />
        </Detail>
        <CommitDetail commitSubject={lastCommit!} />
      </Details>
      <Markdown text={description || ''} />
    </>
  );
}
