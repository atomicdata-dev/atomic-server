import { properties, Resource, useResource, useString } from '@tomic/react';
import React, { useCallback } from 'react';
import { styled } from 'styled-components';
import { FileDropzoneInput } from '../../components/forms/FileDropzone/FileDropzoneInput';
import { transition } from '../../helpers/transition';
import { atomicArgu } from '../../ontologies/atomic-argu';

interface ArticleCoverProps {
  resource: Resource;
  canEdit: boolean;
}

const valueOpts = {
  commit: true,
};

const dropdzoneProps = {
  accept: ['image/*'],
  maxFiles: 1,
  text: 'Click or drop image to use as a cover',
};

export function ArticleCover({
  resource,
  canEdit,
}: ArticleCoverProps): JSX.Element {
  const [coverImageSubject, setCoverImageSubject] = useString(
    resource,
    atomicArgu.properties.coverImage,
    valueOpts,
  );
  const coverImageResource = useResource(coverImageSubject);
  const [coverImageDownloadUrl] = useString(
    coverImageResource,
    properties.file.downloadUrl,
  );

  const setCover = useCallback(
    (files: string[]) => {
      setCoverImageSubject(files[0]);
    },
    [setCoverImageSubject],
  );

  if (!coverImageDownloadUrl && !canEdit) {
    return <></>;
  }

  if (!coverImageDownloadUrl) {
    return (
      <FileDropzoneInput
        {...dropdzoneProps}
        parentResource={resource}
        onFilesUploaded={setCover}
      />
    );
  }

  return (
    <CoverWrapper>
      <CoverImage src={coverImageDownloadUrl} alt='' />
      {canEdit && (
        <DropzoneWrapper>
          <StyledDropzone
            {...dropdzoneProps}
            parentResource={resource}
            onFilesUploaded={setCover}
          />
        </DropzoneWrapper>
      )}
    </CoverWrapper>
  );
}

const CoverImage = styled.img`
  object-fit: cover;
  height: 100%;
  width: 100%;
`;

const DropzoneWrapper = styled.div`
  opacity: 0;
  position: absolute;
  z-index: 2;
  inset: 0;
  height: 100%;
  width: 100%;
  ${transition('opacity')}
`;
const CoverWrapper = styled.div`
  &:hover ${DropzoneWrapper}, &:focus-within ${DropzoneWrapper} {
    opacity: 1 !important;
  }
  position: relative;
  width: calc(100% + ${({ theme }) => theme.margin * 2}rem);
  margin-inline: -${({ theme }) => theme.margin}rem;
  margin-top: -${({ theme }) => theme.margin}rem;
  height: 13rem;
`;

const StyledDropzone = styled(FileDropzoneInput)`
  height: 100%;
  border-bottom-left-radius: 0;
  border-bottom-right-radius: 0;
`;
