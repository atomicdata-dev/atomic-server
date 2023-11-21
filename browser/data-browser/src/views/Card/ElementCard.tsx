import { urls, useResource, useString, useTitle } from '@tomic/react';

import { AtomicLink } from '../../components/AtomicLink';
import Markdown from '../../components/datatypes/Markdown';
import { CardViewProps } from './CardViewProps';

export function ElementCard({ resource }: CardViewProps): JSX.Element {
  const [documentSubject] = useString(resource, urls.properties.parent);
  const document = useResource(documentSubject);
  const [documentTitle] = useTitle(document);

  const [text] = useString(resource, urls.properties.description);

  return (
    <>
      <AtomicLink subject={document.getSubject()}>
        <h2>{documentTitle}</h2>
      </AtomicLink>
      <Markdown text={text ?? ''} />
    </>
  );
}
