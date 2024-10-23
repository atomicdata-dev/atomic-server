import { Resource, server, useNumber, useString } from '@tomic/react';
import { useCallback } from 'react';

export function useFileInfo(resource: Resource) {
  const [downloadUrl] = useString(resource, server.properties.downloadUrl);
  const [mimeType] = useString(resource, server.properties.mimetype);
  const [bytes] = useNumber(resource, server.properties.filesize);

  const downloadFile = useCallback(() => {
    window.open(downloadUrl);
  }, [downloadUrl]);

  if (
    !resource.loading &&
    (downloadUrl === undefined || mimeType === undefined || bytes === undefined)
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
