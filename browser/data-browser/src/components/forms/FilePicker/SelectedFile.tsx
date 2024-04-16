import { Server, useResource } from '@tomic/react';
import { SelectedFileLayout } from './SelectedFileLayout';
import { styled } from 'styled-components';
import { FilePreviewThumbnail } from '../../../views/File/FilePreviewThumbnail';
import { isImageFile } from '../../../views/File/fileTypeUtils';

interface SelectedFileResourceProps {
  subject: string;
  onClear: () => void;
  disabled?: boolean;
}

export function SelectedFileResource({
  subject,
  disabled,
  onClear,
}: SelectedFileResourceProps): React.JSX.Element {
  const resource = useResource<Server.File>(subject);

  return (
    <SelectedFileLayout
      title={resource.title}
      onClear={onClear}
      disabled={disabled}
    >
      <FilePreviewThumbnail resource={resource} />
    </SelectedFileLayout>
  );
}

interface SelectedFileBlobProps {
  file: File;
  disabled?: boolean;
  onClear: () => void;
}

export function SelectedFileBlob({
  file,
  disabled,
  onClear,
}: SelectedFileBlobProps): React.JSX.Element {
  return (
    <SelectedFileLayout
      title={file.name}
      helperText='Will be uploaded when resource is saved'
      onClear={onClear}
      disabled={disabled}
    >
      {isImageFile(file.type) ? (
        <Image src={URL.createObjectURL(file)} alt={file.name} />
      ) : (
        <NoPreview>File preview not available at this time</NoPreview>
      )}
    </SelectedFileLayout>
  );
}

const Image = styled.img`
  width: 100%;
  height: 100%;
  object-fit: cover;
`;

const NoPreview = styled.div`
  background-color: ${({ theme }) => theme.colors.bg1};
  display: grid;
  padding: ${({ theme }) => theme.margin}rem;
  place-items: center;
  color: ${({ theme }) => theme.colors.textLight};
  text-wrap: balance;
  text-align: center;
`;
