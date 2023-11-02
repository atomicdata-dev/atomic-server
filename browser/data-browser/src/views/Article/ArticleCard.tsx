import { core, useString } from '@tomic/react';
import React from 'react';
import { styled } from 'styled-components';
import { AtomicLink } from '../../components/AtomicLink';
import { markdownToPlainText } from '../../helpers/markdown';
import { transitionName } from '../../helpers/transitionName';
import { ViewTransitionProps } from '../../helpers/ViewTransitionProps';
import { CardViewProps } from '../Card/CardViewProps';

export function ArticleCard({ resource }: CardViewProps): JSX.Element {
  const [description] = useString(resource, core.properties.description);
  const truncated = markdownToPlainText(description ?? '').slice(0, 200);

  return (
    <div>
      <AtomicLink subject={resource.getSubject()}>
        <Title subject={resource.getSubject()}>{resource.title}</Title>
      </AtomicLink>
      <p>{truncated}...</p>
    </div>
  );
}

const Title = styled.h2<ViewTransitionProps>`
  white-space: nowrap;
  text-overflow: ellipsis;
  width: 100%;
  overflow: hidden;
  font-size: 1.3rem;
  ${props => transitionName('page-title', props.subject)}
`;
