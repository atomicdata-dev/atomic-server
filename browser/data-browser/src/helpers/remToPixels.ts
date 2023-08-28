/**
 * Converts a rem value to pixels. Take user settings into account.
 */
export function remToPixels(rem: number): number {
  return rem * parseFloat(getComputedStyle(document.documentElement).fontSize);
}
