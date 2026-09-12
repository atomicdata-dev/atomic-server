import { Store } from './store.js';

export interface SearchOpts {
  /** Query HTTP directly, without waiting for the local index or WebSocket.
   * Use after server-side writes whose local replication may still be pending.
   */
  serverOnly?: boolean;
  /** Fetch full resources instead of subjects */
  include?: boolean;
  /** Max of how many results to return */
  limit?: number;
  /** Subjects of resource to scope the search to. This should be a list of parents of the resources you're looking for. */
  parents?: string[] | string;
  /** Property-Value pair of set filters. */
  filters?: {
    [subject: string]: string | number | string[];
  };
}

export interface SemanticSearchOpts {
  /** Fetch full resources instead of subjects */
  include?: boolean;
  /** Max of how many results to return */
  limit?: number;
  parents?: string[] | string;
  isA?: string[] | string;
  rerank?: boolean;
  text_query?: string;
}

const baseURL = (serverURL: string) => {
  const url = new URL(serverURL);
  url.pathname = 'search';

  return url;
};

/** `property:"value" AND …` — exact pairs, consumed by `/search`. */
function buildFilterString(
  filters: Record<string, string | number | string[]>,
): string {
  return Object.entries(filters)
    .map(([key, value]) => {
      if (value === undefined) {
        return undefined;
      }

      if (Array.isArray(value)) {
        return value.map(v => `${key}:"${v}"`).join(' AND ');
      }

      return `${key}:"${value}"`;
    })
    .filter(x => x !== undefined)
    .join(' AND ');
}

/** Returns the URL of the search query. Fetch that and you get your results! */
export function buildSearchSubject(
  serverURL: string,
  query: string,
  opts: SearchOpts = {},
) {
  const { include = false, limit = 30, parents, filters } = opts;
  const url = baseURL(serverURL);

  // Only add filters if there are any keys, and if any key is defined
  const hasFilters =
    filters &&
    Object.keys(filters).length > 0 &&
    Object.values(filters).some(v => {
      if (Array.isArray(v)) {
        return v.length > 0;
      }

      return v !== undefined;
    });

  if (query) url.searchParams.set('q', query);
  if (include) url.searchParams.set('include', include.toString());
  if (limit) url.searchParams.set('limit', limit.toString());
  if (hasFilters) url.searchParams.set('filters', buildFilterString(filters));

  if (parents) {
    if (Array.isArray(parents)) {
      url.searchParams.append('parents', parents.join(','));
    } else {
      url.searchParams.append('parents', parents);
    }
  }

  return url.toString();
}

export function buildSemanticSearchSubject(
  serverURL: string,
  query: string,
  opts: SemanticSearchOpts = {},
) {
  const url = new URL(serverURL);
  url.pathname = 'vector_search';

  url.searchParams.set('q', query);
  if (opts.include) url.searchParams.set('include', opts.include.toString());
  if (opts.limit) url.searchParams.set('limit', opts.limit.toString());
  if (opts.rerank) url.searchParams.set('rerank', opts.rerank.toString());
  if (opts.text_query)
    url.searchParams.set('text_q', opts.text_query.toString());

  if (opts.isA) {
    if (Array.isArray(opts.isA)) {
      url.searchParams.append('is_a', opts.isA.join(','));
    } else {
      url.searchParams.append('is_a', opts.isA);
    }
  }

  if (opts.parents) {
    if (Array.isArray(opts.parents)) {
      url.searchParams.append('parents', opts.parents.join(','));
    } else {
      url.searchParams.append('parents', opts.parents);
    }
  }

  return url.toString();
}

export function removeCachedSearchResults(store: Store) {
  const url = baseURL(store.getServerUrl()).toString();

  // Get all resources that start with the search URL but aren't the search endpoint itself.
  const searchResources = store.clientSideQuery(
    r => r.subject !== url && r.subject.startsWith(url),
  );

  for (const resource of searchResources) {
    store.removeResource(resource.subject, false);
  }
}
