import { Resource, Version, useStore } from '@tomic/react';
import { useState, useEffect } from 'react';
import { dedupeVersions } from './versionHelpers';

export interface UseVersionsResult {
  versions: Version[];
  loading: boolean;
  error: Error | undefined;
}

export function useVersions(resource: Resource): UseVersionsResult {
  const [versions, setVersions] = useState<Version[]>([]);
  const store = useStore();
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<Error | undefined>(undefined);

  useEffect(() => {
    resource
      .getHistory(store)
      .then(history => {
        setVersions(dedupeVersions(history));
      })
      .catch(e => {
        setError(e);
      })
      .finally(() => {
        setLoading(false);
      });
  }, [resource]);

  return { versions, loading, error };
}
