/**
 * Schemes that make a link execute code or inline a document instead of
 * navigating somewhere. Compared after trimming and lowercasing, and with
 * ASCII control characters removed, which is how browsers read a scheme too
 * (`java\nscript:` still runs).
 */
const UNSAFE_SCHEMES = ['javascript:', 'data:', 'vbscript:'];

/**
 * Whether `href` may be handed to the browser as a link target, a
 * `window.open` argument or a `location.assign` destination.
 *
 * Refuses the empty string and any value whose scheme is `javascript:`,
 * `data:` or `vbscript:`. Everything else — `https:`, `mailto:`, `blob:`,
 * relative paths — passes; this is a scheme check, not URL validation.
 */
export function isSafeHref(href: string): boolean {
  if (typeof href !== 'string' || href.length === 0) return false;

  const normalized = Array.from(href)
    .filter(ch => {
      const code = ch.charCodeAt(0);

      return code > 0x1f && code !== 0x7f;
    })
    .join('')
    .trim()
    .toLowerCase();

  if (normalized.length === 0) return false;

  return !UNSAFE_SCHEMES.some(scheme => normalized.startsWith(scheme));
}
