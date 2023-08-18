import { properties, useString, useTitle } from '@tomic/react';
import React from 'react';
import { styled } from 'styled-components';
import { AtomicLink } from '../../components/AtomicLink';
import { markdownToPlainText } from '../../helpers/markdown';
import { CardViewProps } from '../Card/CardViewProps';

export function ArticleCard({ resource }: CardViewProps): JSX.Element {
  const [title] = useTitle(resource);

  const [description] = useString(resource, properties.description);
  const truncated = markdownToPlainText(description ?? '').slice(0, 200);

  return (
    <div>
      <AtomicLink subject={resource.getSubject()}>
        <Title>{title}</Title>
      </AtomicLink>
      <p>{truncated}...</p>
    </div>
  );
}

const Title = styled.h2`
  white-space: nowrap;
  text-overflow: ellipsis;
  width: 100%;
  overflow: hidden;
  font-size: 1.3rem;
`;
