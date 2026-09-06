import {
  Resource,
  Version,
  unknownSubject,
  useStore,
  type HistoryAttribution,
} from '@tomic/react';
import { useState, useEffect, useRef } from 'react';

export interface UseVersionsResult {
  versions: Version[];
  /**
   * Who signed which version, from the signed envelopes the server and the
   * local ClientDb kept. Null while loading or when nothing is retained.
   */
  attribution: HistoryAttribution | null;
  loading: boolean;
  error: Error | undefined;
}

/**
 * Extracts version history from the resource's Loro OpLog.
 * Instant — no network requests needed, no progress bar.
 */
export function useVersions(resource: Resource): UseVersionsResult {
  const store = useStore();
  const [versions, setVersions] = useState<Version[]>([]);
  const [attribution, setAttribution] = useState<HistoryAttribution | null>(
    null,
  );
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<Error | undefined>(undefined);
  const isRunning = useRef(false);

  // Attribution is a network round-trip (and a WASM replay), so it lands
  // after the versions do; the list renders unattributed until then.
  useEffect(() => {
    if (resource.subject === unknownSubject || resource.loading) {
      return;
    }

    let cancelled = false;
    store
      .getHistoryAttribution(resource.subject)
      .then(report => {
        if (!cancelled) setAttribution(report);
      })
      .catch(() => undefined);

    return () => {
      cancelled = true;
    };
  }, [store, resource.subject, resource.loading, versions.length]);

  useEffect(() => {
    if (resource.subject === unknownSubject || resource.loading) {
      return;
    }

    if (isRunning.current) {
      return;
    }

    isRunning.current = true;

    try {
      const history = resource.getLoroHistory();
      setVersions(history);
    } catch (e) {
      console.error('Failed to get Loro history:', e);
      setError(e instanceof Error ? e : new Error(String(e)));
    } finally {
      setLoading(false);
      isRunning.current = false;
    }
  }, [resource, resource.loading]);

  return { versions, attribution, loading, error };
}
