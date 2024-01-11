import { urls, useResource, useString } from '@tomic/react';

import Markdown from '../../components/datatypes/Markdown';
import { CardViewProps } from './CardViewProps';
import { ResourceCardTitle } from './ResourceCardTitle';

export function ElementCard({ resource }: CardViewProps): JSX.Element {
  const [documentSubject] = useString(resource, urls.properties.parent);
  const document = useResource(documentSubject);

  const [text] = useString(resource, urls.properties.description);

  return (
    <>
      <ResourceCardTitle resource={document} />
      <Markdown text={text ?? ''} />
    </>
  );
}
