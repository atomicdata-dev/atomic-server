import React from 'react';
import { useString, properties, useResource } from '@tomic/react';
import { imageMimeTypes, getFileIcon } from '../../helpers/filetypes';
import { ResourceInlineInstanceProps } from './ResourceInline';
import { styled } from 'styled-components';

export function FileInline({
  subject,
}: ResourceInlineInstanceProps): JSX.Element {
  const resource = useResource(subject);
  const [filename] = useString(resource, properties.file.filename);
  const [mimeType] = useString(resource, properties.file.mimetype);
  const [downloadUrl] = useString(resource, properties.file.downloadUrl);

  const isImage = imageMimeTypes.has(mimeType ?? '');
  const Icon = getFileIcon(mimeType ?? '');

  return (
    <Wrapper>
      {isImage ? (
        <Img src={downloadUrl} alt={resource.title} loading='lazy' />
      ) : (
        <Icon />
      )}
      {filename}
    </Wrapper>
  );
}

const Wrapper = styled.span`
  display: inline-flex;
  align-items: center;
  height: 2rem;
  gap: 0.7ch;
  & svg {
    font-size: 1rem;
  }
`;

const Img = styled.img`
  aspect-ratio: 1/1;
  object-fit: cover;
  border-radius: 5px;
  height: 100%;
`;
