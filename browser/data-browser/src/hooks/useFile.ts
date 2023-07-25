import { properties, Resource, useNumber, useString } from '@tomic/react';
import { useCallback } from 'react';

export function useFileInfo(resource: Resource) {
  const [downloadUrl] = useString(resource, properties.file.downloadUrl);
  const [mimeType] = useString(resource, properties.file.mimetype);

  const [bytes] = useNumber(resource, properties.file.filesize);

  const downloadFile = useCallback(() => {
    window.open(downloadUrl);
  }, [downloadUrl]);

  if (
    downloadUrl === undefined ||
    mimeType === undefined ||
    bytes === undefined
  ) {
    throw new Error('File resource is missing properties');
  }

  return {
    downloadFile,
    downloadUrl,
    bytes,
    mimeType,
  };
}
