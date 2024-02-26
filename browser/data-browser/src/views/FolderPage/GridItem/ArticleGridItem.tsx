import { Server, useResource, useSubject } from '@tomic/react';

import { atomicArgu } from '../../../ontologies/atomic-argu';
import { GridItemViewProps } from './GridItemViewProps';
import { Thumbnail } from '../../../components/Thumbnail';

export function ArticleGridItem({ resource }: GridItemViewProps): JSX.Element {
  const [coverImgSubject] = useSubject(
    resource,
    atomicArgu.properties.coverImage,
  );

  const coverImg = useResource<Server.File>(coverImgSubject);

  return <Thumbnail src={coverImg.props.downloadUrl} />;
}
