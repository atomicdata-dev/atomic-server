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

/**
 * `stringToSlug` is a *final form* — it strips leading and trailing dashes,
 * which is right for turning a name like "Meat & fish" into a shortname in one
 * go. Applied to every keystroke it also eats the dash you are in the middle of
 * typing: "is-valid" arrives as "isvalid", because the `-` is trailing for
 * exactly as long as it takes to press the next key. That makes hyphenated
 * shortnames untypeable.
 *
 * So while typing, keep a single trailing dash and let blur finish the job with
 * {@link stringToSlug}.
 */
export function slugWhileTyping(raw: string): string {
  const endsWithSeparator = /[^a-z0-9]$/.test(raw.toLowerCase());

  return stringToSlug(raw) + (endsWithSeparator ? '-' : '');
}
