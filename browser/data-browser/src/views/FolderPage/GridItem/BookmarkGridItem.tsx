import { properties, useString } from '@tomic/react';
import React from 'react';
import styled from 'styled-components';
import { BasicGridItem } from './BasicGridItem';
import { InnerWrapper } from './components';
import { GridItemViewProps } from './GridItemViewProps';

export function BookmarkGridItem({ resource }: GridItemViewProps): JSX.Element {
  const [imageUrl] = useString(resource, properties.bookmark.imageUrl);

  if (!imageUrl) {
    return <BasicGridItem resource={resource} />;
  }

  return (
    <InnerWrapper>
      <Image src={imageUrl} alt='' />
    </InnerWrapper>
  );
}

const Image = styled.img`
  width: 100%;
  height: 100%;
  object-fit: cover;
  object-position: center;
`;
