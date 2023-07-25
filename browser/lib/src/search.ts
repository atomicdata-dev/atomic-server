export interface SearchOpts {
  /** Fetch full resources instead of subjects */
  include?: boolean;
  /** Max of how many results to return */
  limit?: number;
  /** Subject of resource to scope the search to. This should be a parent of the resources you're looking for. */
  scope?: string;
  /** Property-Value pair of set filters. For now, use the `shortname` of the property as the key. */
  filters?: {
    [propertyShortname: string]: string;
  };
}

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
function buildFilterString(filters: { [key: string]: string }): string {
  return Object.entries(filters)
    .map(([key, value]) => {
      return value && value.length > 0 && `${escapeTantivyKey(key)}:"${value}"`;
    })
    .join(' AND ');
}

/** Returns the URL of the search query. Fetch that and you get your results! */
export function buildSearchSubject(
  serverURL: string,
  query: string,
  opts: SearchOpts = {},
) {
  const { include = false, limit = 30, scope, filters } = opts;
  const url = new URL(serverURL);
  url.pathname = 'search';
  query && url.searchParams.set('q', query);
  include && url.searchParams.set('include', include.toString());
  limit && url.searchParams.set('limit', limit.toString());
  // Only add filters if there are any keys, and if any key is defined
  const hasFilters =
    filters &&
    Object.keys(filters).length > 0 &&
    Object.values(filters).filter(v => v && v.length > 0).length > 0;
  hasFilters && url.searchParams.set('filters', buildFilterString(filters));

  if (scope) {
    url.searchParams.set('parent', scope);
  }

  return url.toString();
}
