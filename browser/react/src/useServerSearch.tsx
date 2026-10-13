import { removeCachedSearchResults, SearchOpts } from '@tomic/lib';
import { useEffect, useEffectEvent, useMemo, useState } from 'react';
import { useStore } from './index.js';
import { useDebounce } from './useDebounce.js';
import { useOnValueChange } from './helpers/useOnValueChange.js';

interface SearchResults {
  /** Subject URLs for resources that match the query */
  results: string[];
  loading: boolean;
  error?: Error;
}

interface SearchOptsHook extends SearchOpts {
  /**
   * Debouncing makes queries slower, but prevents sending many request. Number
   * respresents milliseconds.
   */
  debounce?: number;
  allowEmptyQuery?: boolean;
}

/** Escape values for use in filter string */
export const escapeFilterValue = (value: string) =>
  value.replace(/[+^`:{}"[\]()!\\*\s]/gm, '\\$&');

/** Pass a query to search the current server */
export function useServerSearch(
  query: string | undefined,
  opts: SearchOptsHook = {},
): SearchResults {
  const { debounce = 50, allowEmptyQuery = false, ...searchOpts } = opts;
  const store = useStore();
  const [results, setResults] = useState<string[]>([]);
  const [error, setError] = useState<Error | undefined>(undefined);
  const [loading, setLoading] = useState(false);
  const debouncedQuery = useDebounce(query, debounce) ?? '';

  // Memoize searchOpts by content, not reference. searchOpts is a new object
  // every render (destructured from the caller's inline object literal).
  const searchOptsKey = JSON.stringify(searchOpts);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const memoizedSearchOpts = useMemo(() => searchOpts, [searchOptsKey]);

  useOnValueChange(() => {
    if (debouncedQuery) {
      setLoading(true);
    }

    if (!debouncedQuery && !allowEmptyQuery) {
      setResults([]);
      setLoading(false);
    }
  }, [debouncedQuery, allowEmptyQuery]);

  const updateResults = useEffectEvent(
    (r: string[], relevantQuery: string, relevantOpts: SearchOpts) => {
      // If the query became empty since the last fetch, don't update the results
      if (
        relevantQuery !== debouncedQuery ||
        relevantOpts !== memoizedSearchOpts
      ) {
        return;
      }

      setResults(r);
    },
  );

  useEffect(() => {
    if (!debouncedQuery && !allowEmptyQuery) {
      return;
    }

    // The server's Tantivy index commits on a throttle (~5s), so a resource
    // created moments ago is not searchable immediately. A single query
    // would miss it and never refresh — the user (or a test) sees no result
    // for something that exists. While results are empty, retry a bounded
    // number of times so a freshly-indexed resource appears on its own.
    let cancelled = false;
    let attempt = 0;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    const MAX_RETRIES = 4;
    const RETRY_DELAY_MS = 2000;

    const runSearch = () => {
      // Show local hits right away; `loading` stays true until the server
      // answered, so the UI can combine early results with a pending state.
      const onPartial = (partial: string[]) => {
        if (cancelled || partial.length === 0) {
          return;
        }

        updateResults(partial, debouncedQuery, memoizedSearchOpts);
      };

      store
        .search(debouncedQuery, { ...memoizedSearchOpts, onPartial })
        .then(r => {
          if (cancelled) {
            return;
          }

          updateResults(r, debouncedQuery, memoizedSearchOpts);
          setError(undefined);

          if (r.length === 0 && attempt < MAX_RETRIES) {
            attempt++;
            retryTimer = setTimeout(runSearch, RETRY_DELAY_MS);
          }
        })
        .catch(e => {
          if (cancelled) {
            return;
          }

          setError(e);

          // A *transient* failure (server contention / request timeout under
          // load) must not leave the overlay permanently blank for a resource
          // that exists. Retry on the same bounded schedule as the empty-result
          // path above; only give up — and clear — once retries are exhausted.
          if (attempt < MAX_RETRIES) {
            attempt++;
            retryTimer = setTimeout(runSearch, RETRY_DELAY_MS);
          } else {
            setResults([]);
          }
        })
        .finally(() => {
          if (!cancelled) {
            setLoading(false);
          }
        });
    };

    runSearch();

    return () => {
      cancelled = true;

      if (retryTimer) {
        clearTimeout(retryTimer);
      }
    };
  }, [store, allowEmptyQuery, debouncedQuery, memoizedSearchOpts]);

  // Remove cached results when component unmounts.
  useEffect(() => {
    return () => {
      removeCachedSearchResults(store);
    };
  }, [store]);

  return {
    results,
    loading,
    error,
  };
}
