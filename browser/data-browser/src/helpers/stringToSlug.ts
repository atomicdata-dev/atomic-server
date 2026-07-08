/**
 * A name turned into a valid slug: lowercase letters and numbers, single dashes
 * between them.
 *
 * Every non-slug character becomes a separator *before* runs are collapsed. Done
 * the other way around, "Meat & fish" became `meat--fish` — the `&` was dropped
 * only after the collapse, leaving the two dashes it had been sitting between.
 * That is a rejected shortname, and it made the Grocery list template
 * uncreatable.
 */
export function stringToSlug(str: string): string {
  return str
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '');
}

export function stringToSlugStrict(str: string): string {
  return str
    .toLowerCase()
    .replace(/[^\w\s-]+/g, '')
    .trim()
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '');
}
