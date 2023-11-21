import { useState, useEffect } from 'react';
import {
  Client,
  Resource,
  urls,
  useResources,
  useStore,
  useDebounce,
} from '@tomic/react';
import { QuickScore } from 'quick-score';

/**
 * Pass a query and an set of pre-defined subjects. If you don't pass these
 * subjects, it will search all subjects. Use the 'disabled' argument to disable
 * this very expensive hook as much as possible
 */
export function useLocalSearch(
  query: string,
  subjects?: string[],
  disabled?: boolean,
): Hit[] {
  const [index, setIndex] = useState<SearchIndex | undefined>(undefined);
  const [results, setResults] = useState<Hit[]>([]);
  const store = useStore();
  let resources = useResources(subjects || []);
  // Calculate the query takes a while, so we debounce it
  const debouncedQuery = useDebounce(query, 40);

  // The Resources prop can change very quickly, as multiple resources can be fetched in a short timespan.
  // This will cause the search index to be rebuilt every time, so we debounce the resources.
  if (subjects === undefined) {
    resources = store.resources;
  }

  const resourcesD = useDebounce(resources, 100);

  useEffect(() => {
    if (disabled) {
      return;
    }

    setIndex(constructIndex(resourcesD));
  }, [resourcesD, disabled]);

  useEffect(() => {
    if (disabled) {
      return;
    }

    if (index === undefined) {
      return;
    }

    // For some reason, searching for a URL as query takes infinitely long..?
    if (Client.isValidSubject(debouncedQuery)) {
      return;
    }

    const searchResults = index && index.search(debouncedQuery);
    setResults(searchResults);
  }, [debouncedQuery, index, disabled]);

  // Return the width so we can use it in our components
  return results;
}

/**
 * Constructs a QuickScore search index from all resources in the store. Does
 * not index commits or resources that are not ready
 */
function constructIndex(resourceMap?: Map<string, Resource>): SearchIndex {
  const resources = Array.from(resourceMap?.values() || []);
  const dataArray = resources.reduce((array: FoundResource[], resource) => {
    // Don't index resources that are loading / errored
    if (!resource.isReady()) return array;

    // ... or have no subject
    if (resource.getSubject() === undefined) {
      return array;
    }

    // Don't index commits
    if (resource.getClasses().includes(urls.classes.commit)) {
      return array;
    }

    // QuickScore can't handle URLs as keys, so I serialize all values of propvals to a single string. https://github.com/fwextensions/quick-score/issues/11
    const propvalsString = JSON.stringify(
      Array.from(resource.getPropVals().values()).sort().join(' \n '),
    );
    const searchResource: FoundResource = {
      subject: resource.getSubject(),
      valuesArray: propvalsString,
    };
    array.push(searchResource);

    return array;
  }, []);
  // QuickScore requires explicit keys to search through. These should match the keys in FoundResource
  const qsOpts = { keys: ['subject', 'valuesArray'] };
  const qs = new QuickScore(dataArray, qsOpts);

  return qs;
}

/** An instance of QuickScore. See https://fwextensions.github.io/quick-score/ */
interface SearchIndex {
  search: (query: string) => Hit[];
}

export interface Hit {
  item: FoundResource;
}

interface FoundResource {
  // The subject of the found resource
  subject: string;
  // JSON serialized array of values combinations
  valuesArray: string;
}
