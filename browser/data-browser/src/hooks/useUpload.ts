import {
  AtomicError,
  properties,
  Resource,
  useArray,
  useStore,
} from '@tomic/react';
import { useCallback, useState } from 'react';

export interface UseUploadResult {
  /** Uploads files to the upload endpoint and returns the created subjects. */
  upload: (acceptedFiles: File[]) => Promise<string[]>;
  isUploading: boolean;
  error: Error | undefined;
}

const opts = {
  commit: true,
};

export function useUpload(parentResource: Resource): UseUploadResult {
  const store = useStore();
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<Error | undefined>(undefined);
  const [subResources, setSubResources] = useArray(
    parentResource,
    properties.subResources,
    opts,
  );

  const upload = useCallback(
    async (acceptedFiles: File[]) => {
      try {
        setError(undefined);
        setIsUploading(true);
        const netUploaded = await store.uploadFiles(
          acceptedFiles,
          parentResource.getSubject(),
        );
        const allUploaded = [...netUploaded];
        setIsUploading(false);
        await setSubResources([...subResources, ...allUploaded]);
        await parentResource.save(store);

        return allUploaded;
      } catch (e) {
        setError(new AtomicError(e?.message));
        setIsUploading(false);

        return [];
      }
    },
    [parentResource, store, setSubResources, subResources],
  );

  return {
    upload,
    isUploading,
    error,
  };
}
