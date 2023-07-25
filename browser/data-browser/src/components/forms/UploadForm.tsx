import React, { useCallback, useState } from 'react';
import { Resource } from '@tomic/react';
import { useDropzone } from 'react-dropzone';
import { Button } from '../Button';
import FilePill from '../FilePill';
import { ErrMessage } from './InputStyles';
import { useUpload } from '../../hooks/useUpload';

interface UploadFormProps {
  /**
   * The resource which the newly uploaded files will refer to as parent. In
   * other words, the newly uploaded files will be children of this resource.
   */
  parentResource: Resource;
}

/** Shows a Button + drag and drop interface for uploading files */
export default function UploadForm({
  parentResource,
}: UploadFormProps): JSX.Element {
  const [uploadedFiles, setUploadedFiles] = useState<string[]>([]);
  const { upload, isUploading, error } = useUpload(parentResource);

  const onDrop = useCallback(
    async (files: File[]) => {
      const result = await upload(files);

      setUploadedFiles(result);
    },
    [upload],
  );

  const { getRootProps, getInputProps, isDragActive } = useDropzone({ onDrop });

  if (parentResource.new) {
    return <p>You can add attachments after saving the resource.</p>;
  }

  return (
    <div>
      <div {...getRootProps()}>
        <input {...getInputProps()} />
        {isDragActive ? (
          <p>{'Drop the files here ...'}</p>
        ) : (
          <Button
            subtle
            onClick={() => null}
            loading={isUploading ? 'Uploading...' : undefined}
          >
            Upload file(s)...
          </Button>
        )}
        {error && <ErrMessage>{error.message}</ErrMessage>}
      </div>
      {uploadedFiles.length > 0 &&
        uploadedFiles.map(fileSubject => (
          <FilePill key={fileSubject} subject={fileSubject} />
        ))}
    </div>
  );
}
