import { Store } from './index.js';

export interface SearchOpts {
  /** Fetch full resources instead of subjects */
  include?: boolean;
  /** Max of how many results to return */
  limit?: number;
  /** Subjects of resource to scope the search to. This should be a list of parents of the resources you're looking for. */
  parents?: string[] | string;
  /** Property-Value pair of set filters. */
  filters?: {
    [subject: string]: string;
  };
}

const baseURL = (serverURL: string) => {
  const url = new URL(serverURL);
  url.pathname = 'search';

  return url;
};

// https://github.com/quickwit-oss/tantivy/blob/064518156f570ee2aa03cf63be6d5605a96d6285/query-grammar/src/query_grammar.rs#L19
const specialCharsTantivy = [
  '+',
  '^',
  '`',
  ':',
  '{',
  '}',
  '"',
  '[',
  ']',
  '(',
  ')',
  '!',
  '\\',
  '*',
  ' ',
  // The dot is escaped, even though it's not in Tantivy's list.
  '.',
];

/** escape the key conform to Tantivy syntax, escaping all specialCharsTantivy */
export function escapeTantivyKey(key: string) {
  return key.replace(
    new RegExp(`([${specialCharsTantivy.join('\\')}])`, 'g'),
    '\\$1',
  );
}

/** Uses Tantivy query syntax */
function buildFilterString(filters: Record<string, string>): string {
  return Object.entries(filters)
    .map(([key, value]) => {
      return value && `${escapeTantivyKey(key)}:"${value}"`;
    })
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
    Object.values(filters).filter(v => v && v.length > 0).length > 0;

  query && url.searchParams.set('q', query);
  include && url.searchParams.set('include', include.toString());
  limit && url.searchParams.set('limit', limit.toString());
  hasFilters && url.searchParams.set('filters', buildFilterString(filters));

  if (parents) {
    if (Array.isArray(parents)) {
      url.searchParams.append('parents', parents.join(','));
    } else {
      url.searchParams.append('parents', parents);
    }
  }
  // parents && url.searchParams.set('parents', JSON.stringify(parents));

  return url.toString();
}

export function removeCachedSearchResults(store: Store) {
  const url = baseURL(store.getServerUrl()).toString();

  // Get all resources that start with the search URL but aren't the search endpoint itself.
  const searchResources = store.clientSideQuery(
    r => r.getSubject() !== url && r.getSubject().startsWith(url),
  );

  for (const resource of searchResources) {
    store.removeResource(resource.getSubject());
  }
}
