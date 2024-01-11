import { urls, useResource, useString } from '@tomic/react';

import Markdown from '../../components/datatypes/Markdown';
import { CardViewProps } from './CardViewProps';
import { ResourceCardTitle } from './ResourceCardTitle';
import { Column } from '../../components/Row';

export function ElementCard({ resource }: CardViewProps): JSX.Element {
  const [documentSubject] = useString(resource, urls.properties.parent);
  const document = useResource(documentSubject);

  const [text] = useString(resource, urls.properties.description);

  return (
    <Column gap='0.5rem'>
      <ResourceCardTitle resource={document} />
      <Markdown text={text ?? ''} />
    </Column>
  );
}
