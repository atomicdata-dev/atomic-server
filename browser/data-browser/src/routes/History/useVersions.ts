import { Resource, Version, unknownSubject } from '@tomic/react';
import { useState, useEffect, useRef, useTransition } from 'react';
import { dedupeVersions } from './versionHelpers';

export interface UseVersionsResult {
  versions: Version[];
  loading: boolean;
  progress: number;
  error: Error | undefined;
}

export function useVersions(resource: Resource): UseVersionsResult {
  const [versions, setVersions] = useState<Version[]>([]);
  const [progress, setProgress] = useState(0);
  const isRunning = useRef(false);
  const [_, startTransition] = useTransition();
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<Error | undefined>(undefined);

  useEffect(() => {
    if (resource.getSubject() === unknownSubject) {
      return;
    }

    if (isRunning.current) {
      return;
    }

    startTransition(() => {
      (async () => {
        try {
          isRunning.current = true;
          const history = await resource.getHistory(setProgress);
          const dedupedVersions = dedupeVersions(history);
          setVersions(dedupedVersions);
        } catch (e) {
          setError(e);
        } finally {
          setLoading(false);
          isRunning.current = false;
        }
      })();
    });
  }, [resource]);

  return { versions, loading, error, progress };
}
