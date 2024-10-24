import { Resource, server, useNumber, useString } from '@tomic/react';
import { useCallback } from 'react';

type FileInfo =
  | {
      loading: true;
      downloadUrl: undefined;
      downloadFile: () => void;
      mimeType: undefined;
      bytes: undefined;
    }
  | {
      loading: false;
      downloadUrl: string;
      downloadFile: () => void;
      mimeType: string;
      bytes: number;
    };

export function useFileInfo(resource: Resource): FileInfo {
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

  if (resource.loading) {
    return {
      loading: true,
      downloadUrl: undefined,
      downloadFile,
      mimeType: undefined,
      bytes: undefined,
    };
  }

  return {
    loading: false,
    downloadFile,
    downloadUrl: downloadUrl!,
    bytes: bytes!,
    mimeType: mimeType!,
  };
}
