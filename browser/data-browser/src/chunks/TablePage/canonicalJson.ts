/**
 * The form the query index stores a JSON value in: keys sorted at every level,
 * no whitespace. Undefined when `text` is not valid JSON, so a half-typed value
 * is left alone.
 */
export function canonicalJson(text: string): string | undefined {
  try {
    return JSON.stringify(sortKeys(JSON.parse(text)));
  } catch {
    return undefined;
  }
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }

  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([key, inner]) => [key, sortKeys(inner)]),
    );
  }

  return value;
}
