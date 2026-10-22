import type { RouterHistory } from '@tanstack/react-router';

/**
 * Makes the history's first entry the current one, so that after replacing it
 * the page has nothing to go back to. A pre-loaded page is shown other
 * resources while nobody looks (`show`), and each of those is an entry: when
 * the app then opens a resource in it, back would walk through them (a
 * completely different resource) instead of leaving the page. Entries after
 * the current one stay in the list, but a push drops them and the page never
 * goes forward.
 */
export function goToFirstEntry(history: RouterHistory): void {
  if (history.canGoBack()) {
    history.go(-history.length);
  }
}
