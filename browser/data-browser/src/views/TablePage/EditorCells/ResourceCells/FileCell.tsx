import { useResource, useString, useTitle, Image, server } from '@tomic/react';

import { styled } from 'styled-components';
import { getFileIcon, imageMimeTypes } from '../../../../helpers/filetypes';
import { ResourceCellProps } from '../Type';
import { SimpleResourceLink } from './SimpleResourceLink';

export function FileCell({ subject }: ResourceCellProps) {
  const resource = useResource(subject);
  const [title] = useTitle(resource);
  const [mimeType] = useString(resource, server.properties.mimetype);

  const isImage = imageMimeTypes.has(mimeType ?? '');
  const Icon = getFileIcon(mimeType ?? '');

  return (
    <Wrapper>
      {isImage ? (
        <StyledLink resource={resource} tabIndex={-1} aria-hidden>
          <Img
            subject={subject}
            alt={title}
            loading='lazy'
            sizeIndication={'100px'}
          />
        </StyledLink>
      ) : (
        <Icon />
      )}
      <StyledLink resource={resource}>{title}</StyledLink>
    </Wrapper>
  );
}

const Img = styled(Image)`
  width: calc(var(--table-row-height) - 6px);
  height: calc(var(--table-row-height) - 6px);
  aspect-ratio: 1/1;
  object-fit: cover;
  border-radius: 5px;
  vertical-align: middle;
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
  align-items: center;
`;
