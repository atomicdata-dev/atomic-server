import { buildSearchSubject, SearchOpts, urls } from '@tomic/lib';
import { useEffect, useMemo, useState } from 'react';
import { useArray, useDebounce, useResource, useServerURL } from './index.js';

interface SearchResults {
  /** Subject URLs for resources that match the query */
  results: string[];
  loading: boolean;
  error?: Error;
}

const emptyArray = [];

interface SearchOptsHook extends SearchOpts {
  /**
   * Debouncing makes queries slower, but prevents sending many request. Number
   * respresents milliseconds.
   */
  debounce?: number;
}

/** Pass a query to search the current server */
export function useServerSearch(
  query: string | undefined,
  opts: SearchOptsHook = {},
): SearchResults {
  const { debounce = 50 } = opts;

  const [results, setResults] = useState<string[]>([]);
  const [serverURL] = useServerURL();
  // Calculating the query takes a while, so we debounce it
  const debouncedQuery = useDebounce(query, debounce) ?? '';

  const searchSubjectURL: string = useMemo(
    () => buildSearchSubject(serverURL, debouncedQuery, opts),
    [debouncedQuery, opts, serverURL],
  );

  const resource = useResource(searchSubjectURL, {
    noWebSocket: true,
  });

  const [resultsIn] = useArray(resource, urls.properties.endpoint.results);

  // Only set new results if the resource is no longer loading, which improves UX
  useEffect(() => {
    if (!resource.loading && resultsIn) {
      setResults(resultsIn as string[]);
    }
  }, [
    // Prevent re-rendering if the resultsIn is the same
    resultsIn?.toString(),
    resource.loading,
  ]);

  if (!query) {
    return {
      results: emptyArray,
      loading: false,
      error: undefined,
    };
  }

  // Return the width so we can use it in our components
  return { results, loading: resource.loading, error: resource.error };
}
