import { urls, useString, useTitle } from '@tomic/react';
import React from 'react';
import { styled } from 'styled-components';
import { AtomicLink } from '../../components/AtomicLink';
import Markdown from '../../components/datatypes/Markdown';
import {
  ExternalLink,
  ExternalLinkVariant,
} from '../../components/ExternalLink';
import { CardViewProps } from './CardViewProps';

export function BookmarkCard({ resource }: CardViewProps): JSX.Element {
  const [title] = useTitle(resource);
  const [url] = useString(resource, urls.properties.bookmark.url);
  const [preview] = useString(resource, urls.properties.bookmark.preview);

  return (
    <>
      <AtomicLink subject={resource.getSubject()}>
        <Title>{title}</Title>
      </AtomicLink>
      <ExternalLink to={url!} variant={ExternalLinkVariant.Button}>
        Open site
      </ExternalLink>
      {preview && (
        <MarkdownWrapper>
          <Markdown maxLength={1000} renderGFM text={preview} />
        </MarkdownWrapper>
      )}
    </>
  );
}

const Title = styled.h2`
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  line-height: 1.2;
`;

const MarkdownWrapper = styled.div`
  margin-top: ${p => p.theme.margin}rem;
  margin-inline: -${p => p.theme.margin}rem;
  padding: ${p => p.theme.margin}rem;
  background-color: ${props => props.theme.colors.bgBody};
  border-top: 1px solid ${props => props.theme.colors.bg2};

  img {
    border-radius: ${props => props.theme.radius};
  }
`;
