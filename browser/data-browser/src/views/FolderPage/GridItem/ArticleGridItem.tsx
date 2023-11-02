import { Server, useResource, useSubject } from '@tomic/react';
import React from 'react';
import { atomicArgu } from '../../../ontologies/atomic-argu';
import { GridItemViewProps } from './GridItemViewProps';
import { GridItemWithImage } from './GridItemWithImage';

export function ArticleGridItem({ resource }: GridItemViewProps): JSX.Element {
  const [coverImgSubject] = useSubject(
    resource,
    atomicArgu.properties.coverImage,
  );

  const coverImg = useResource<Server.File>(coverImgSubject);

  return <GridItemWithImage src={coverImg.props.downloadUrl} />;
}
