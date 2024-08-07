import { useString, useResource, server, Image } from '@tomic/react';
import { imageMimeTypes, getFileIcon } from '../../helpers/filetypes';
import { ResourceInlineInstanceProps } from './ResourceInline';
import { styled } from 'styled-components';
const THUMB_SIZE = '2rem';

export function FileInline({
  subject,
}: ResourceInlineInstanceProps): JSX.Element {
  const resource = useResource(subject);
  const [filename] = useString(resource, server.properties.filename);
  const [mimeType] = useString(resource, server.properties.mimetype);

  const isImage = imageMimeTypes.has(mimeType ?? '');
  const Icon = getFileIcon(mimeType ?? '');

  return (
    <Wrapper>
      {isImage ? (
        <Img
          subject={subject}
          alt={resource.title}
          loading='lazy'
          sizeIndication={THUMB_SIZE}
        />
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
  height: ${THUMB_SIZE};
  gap: 0.7ch;
  & svg {
    font-size: 1rem;
  }
`;

const Img = styled(Image)`
  object-fit: cover;
  border-radius: 5px;
  height: ${THUMB_SIZE};
  width: ${THUMB_SIZE};
`;
