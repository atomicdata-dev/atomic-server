import { properties, useArray, useResource, useString } from '@tomic/react';

import Markdown from '../../../components/datatypes/Markdown';
import { GridItemDescription, InnerWrapper } from './components';
import { GridItemViewProps } from './GridItemViewProps';

export function DocumentGridItem({ resource }: GridItemViewProps): JSX.Element {
  const [elements] = useArray(resource, properties.document.elements);
  const firstElementResource = useResource(elements[0]);
  const [text] = useString(firstElementResource, properties.description);

  return (
    <InnerWrapper>
      <GridItemDescription>
        <Markdown text={text ?? ''} />
      </GridItemDescription>
    </InnerWrapper>
  );
}
