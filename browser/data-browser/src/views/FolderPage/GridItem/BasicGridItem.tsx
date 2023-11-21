import { properties, useString } from '@tomic/react';

import { GridItemDescription, InnerWrapper } from './components';
import { GridItemViewProps } from './GridItemViewProps';

/** A simple view that only renders the description */
export function BasicGridItem({ resource }: GridItemViewProps): JSX.Element {
  const [description] = useString(resource, properties.description);

  return (
    <InnerWrapper>
      <GridItemDescription>{description}</GridItemDescription>
    </InnerWrapper>
  );
}
