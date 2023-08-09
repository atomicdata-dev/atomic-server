import { useString, properties } from '@tomic/react';
import React from 'react';
import { CommitDetail } from '../components/CommitDetail';
import { ContainerNarrow } from '../components/Containers';
import Markdown from '../components/datatypes/Markdown';
import { Details } from '../components/Detail';
import { ResourceInline } from './ResourceInline';
import { ResourcePageProps } from './ResourcePage';

/** Full page Message view that should (in the future) render replies */
export function MessagePage({ resource }: ResourcePageProps) {
  const [description] = useString(resource, properties.description);
  const [parent] = useString(resource, properties.parent);
  const [lastCommit] = useString(resource, properties.commit.lastCommit);

  return (
    <ContainerNarrow>
      <h3>
        Message in <ResourceInline subject={parent!} />
      </h3>
      <Details>
        <CommitDetail commitSubject={lastCommit!} />
      </Details>
      <Markdown text={description || ''} />
    </ContainerNarrow>
  );
}
