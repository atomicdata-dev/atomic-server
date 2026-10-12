/**
 * Colours the characters past a text question's `maxLength` red, inside the
 * input itself.
 *
 * Two young APIs together: the CSS Custom Highlight API paints a range
 * without wrapping it in an element, and `createValueRange()` — the "opaque
 * range" proposal — is the only way to name a slice of a form control's
 * *value*, which has no DOM nodes to build an ordinary `Range` from. Firefox
 * and recent Chrome have both; everything else has neither.
 *
 * So this is strictly decoration. The counter going red, the field's
 * `aria-invalid` border and the refused submit are what actually tell the
 * visitor they are over — all of them plain DOM. When the APIs are missing
 * (or throw, which a proposal-stage API is allowed to do) the highlight
 * simply never appears.
 */

/** The registered highlight's name. Paired with the `::highlight()` rule in
 * `style.css`; a browser that cannot parse that selector drops the rule and
 * the ranges registered here paint nothing. */
export const OVERFLOW_HIGHLIGHT = 'atomic-form-overflow';

/** `createValueRange(start, end)` returns a range over a form control's
 * value. Not in `lib.dom` yet, and absent at runtime on most browsers —
 * hence optional, so every call site has to check. */
type ValueRangeCapable = {
  createValueRange?: (start: number, end: number) => AbstractRange;
};

/**
 * The one `Highlight` every over-long field registers its range in — the
 * registry is keyed by name and document-wide, so a second field must not
 * replace the first one's entry.
 *
 * `undefined` means "not available here", which is the common case; the
 * whole feature is skipped from then on.
 */
function overflowHighlight(): Highlight | undefined {
  if (
    typeof CSS === 'undefined' ||
    !CSS.highlights ||
    typeof Highlight === 'undefined'
  ) {
    return undefined;
  }

  try {
    const existing = CSS.highlights.get(OVERFLOW_HIGHLIGHT);

    if (existing) return existing;

    const created = new Highlight();
    CSS.highlights.set(OVERFLOW_HIGHLIGHT, created);

    return created;
  } catch {
    return undefined;
  }
}

/**
 * Paints `element`'s characters from `start` to the end of its value.
 * Returns the cleanup that removes them again, or `undefined` when nothing
 * was painted — so a caller can `return highlightOverflow(...)` straight out
 * of an effect.
 */
export function highlightOverflow(
  element: HTMLInputElement | HTMLTextAreaElement,
  start: number,
): (() => void) | undefined {
  const createValueRange = (element as ValueRangeCapable).createValueRange;

  if (typeof createValueRange !== 'function') return undefined;

  const highlight = overflowHighlight();

  if (!highlight) return undefined;

  try {
    const range = createValueRange.call(element, start, element.value.length);
    highlight.add(range);

    return () => {
      highlight.delete(range);
    };
  } catch {
    return undefined;
  }
}
