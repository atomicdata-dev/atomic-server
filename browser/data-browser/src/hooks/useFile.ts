import {
  Resource,
  isSafeHref,
  server,
  useFileObjectUrl,
  useNumber,
  useString,
} from '@tomic/react';
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
  const [serverDownloadUrl] = useString(
    resource,
    server.properties.downloadUrl,
  );
  const [mimeType] = useString(resource, server.properties.mimetype);
  const [bytes] = useNumber(resource, server.properties.filesize);
  // Local-first: when the browser already has the bytes (just-uploaded file,
  // offline, or anything cached in the WASM clientDb) prefer the in-memory
  // blob URL. The server `downloadURL` returns 404 immediately after upload
  // until the BLOB_RESPONSE round-trip completes — without this, the preview
  // would flash a broken image on its way to "loaded".
  const localUrl = useFileObjectUrl(resource);
  const downloadUrl = localUrl ?? serverDownloadUrl;

  const downloadFile = useCallback(() => {
    // The URL is the resource's own claim; refuse anything that would run
    // rather than download.
    if (downloadUrl && isSafeHref(downloadUrl)) {
      window.open(downloadUrl);
    }
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
