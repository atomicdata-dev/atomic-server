import { properties, useString, useTitle } from '@tomic/react';
import React from 'react';
import { styled } from 'styled-components';
import { getFileIcon, imageMimeTypes } from '../../../../helpers/filetypes';
import { ResourceCellProps } from '../Type';
import { SimpleResourceLink } from './SimpleResourceLink';

export function FileCell({ resource }: ResourceCellProps) {
  const [title] = useTitle(resource);
  const [mimeType] = useString(resource, properties.file.mimetype);
  const [downloadUrl] = useString(resource, properties.file.downloadUrl);

  const isImage = imageMimeTypes.has(mimeType ?? '');
  const Icon = getFileIcon(mimeType ?? '');

  return (
    <Wrapper>
      {isImage ? (
        <StyledLink resource={resource} tabIndex={-1} aria-hidden>
          <Img src={downloadUrl} alt={title} loading='lazy' />
        </StyledLink>
      ) : (
        <Icon />
      )}
      <StyledLink resource={resource}>{title}</StyledLink>
    </Wrapper>
  );
}

const Img = styled.img`
  width: calc(var(--table-row-height) - 6px);
  aspect-ratio: 1/1;
  object-fit: cover;
  border-radius: 5px;
`;

const Wrapper = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: ${p => p.theme.colors.main};
`;

const StyledLink = styled(SimpleResourceLink)`
  display: flex;
  height: fit-content;
`;
