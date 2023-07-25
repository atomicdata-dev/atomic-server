import { Resource } from '@tomic/react';
import React, { useCallback, useEffect } from 'react';
import { useDropzone } from 'react-dropzone';
import { FaUpload } from 'react-icons/fa';
import styled, { keyframes } from 'styled-components';
import { ErrMessage } from '../InputStyles';
import { useUpload } from '../../../hooks/useUpload';

export interface FileDropZoneProps {
  parentResource: Resource;
  onFilesUploaded?: (files: string[]) => void;
}

/**
 * A dropzone for adding files. Renders its children by default, unless you're
 * holding a file, an error occurred, or it's uploading.
 */
export function FileDropZone({
  parentResource,
  children,
  onFilesUploaded,
}: React.PropsWithChildren<FileDropZoneProps>): JSX.Element {
  const { upload, isUploading, error } = useUpload(parentResource);
  const dropzoneRef = React.useRef<HTMLDivElement>(null);
  const onDrop = useCallback(
    async (files: File[]) => {
      const uploaded = await upload(files);
      onFilesUploaded?.(uploaded);
    },
    [upload],
  );

  const { getRootProps, isDragActive } = useDropzone({ onDrop });

  // Move the dropzone down if the user has scrolled down.
  useEffect(() => {
    if (isDragActive && dropzoneRef.current) {
      const rect = dropzoneRef.current.getBoundingClientRect();

      if (rect.top < 0) {
        dropzoneRef.current.style.top = `calc(${Math.abs(rect.top)}px + 1rem)`;
      }
    }
  }, [isDragActive]);

  return (
    <Root
      {...getRootProps()}
      // For some reason this is tabbable by default, but it does not seem to actually help users.
      // Let's disable it.
      tabIndex={-1}
    >
      {isUploading && <p>{'Uploading...'}</p>}
      {error && <ErrMessage>{error.message}</ErrMessage>}
      {children}
      {isDragActive && (
        <VisualDropzone ref={dropzoneRef}>
          <TextWrapper>
            <FaUpload /> Drop files here to upload.
          </TextWrapper>
        </VisualDropzone>
      )}
    </Root>
  );
}

const Root = styled.div`
  height: 100%;
  position: relative;
`;

const fadeIn = keyframes`
  from {
    opacity: 0;
    backdrop-filter: blur(0px);
  }
  to {
    opacity: 1;
    backdrop-filter: blur(10px);
  }
`;

const VisualDropzone = styled.div`
  position: absolute;
  inset: 0;
  height: 90vh;
  background-color: ${p =>
    p.theme.darkMode ? 'rgba(0, 0, 0, 0.8)' : 'rgba(255, 255, 255, 0.8)'};
  backdrop-filter: blur(10px);
  border: 3px dashed ${p => p.theme.colors.textLight};
  border-radius: ${p => p.theme.radius};
  display: grid;
  place-items: center;
  font-size: 1.8rem;
  color: ${p => p.theme.colors.textLight};
  animation: 0.1s ${fadeIn} ease-in;
`;

const TextWrapper = styled.div`
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: ${p => p.theme.margin}rem;
`;
