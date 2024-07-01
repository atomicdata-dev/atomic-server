import { core, useString } from '@tomic/react';

import { styled } from 'styled-components';
import { AtomicLink } from '../../components/AtomicLink';
import { markdownToPlainText } from '../../helpers/markdown';
import {
  PAGE_TITLE_TRANSITION_TAG,
  transitionName,
} from '../../helpers/transitionName';
import { ViewTransitionProps } from '../../helpers/ViewTransitionProps';
import { CardViewProps } from '../Card/CardViewProps';

const TRUNCATE_THRESHOLD = 200;

export function ArticleCard({ resource }: CardViewProps): JSX.Element {
  const [description] = useString(resource, core.properties.description);
  const truncated = markdownToPlainText(description ?? '').slice(
    0,
    TRUNCATE_THRESHOLD,
  );

  const truncationMark = truncated.length < TRUNCATE_THRESHOLD ? '' : '...';

  return (
    <div>
      <AtomicLink subject={resource.subject}>
        <Title subject={resource.subject}>{resource.title}</Title>
      </AtomicLink>
      <p>
        {truncated}
        {truncationMark}
      </p>
    </div>
  );
}

const Title = styled.h2<ViewTransitionProps>`
  white-space: nowrap;
  text-overflow: ellipsis;
  width: 100%;
  overflow: hidden;
  font-size: 1.3rem;
  ${props => transitionName(PAGE_TITLE_TRANSITION_TAG, props.subject)}
`;
