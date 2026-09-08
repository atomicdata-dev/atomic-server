/** Cancel page-owned reads when the browser discards the document. */
let owner: Window | undefined;
let controller: AbortController | undefined;

export function pageRequestSignal(): AbortSignal | undefined {
  if (typeof window === 'undefined' || !window.addEventListener) return;

  if (owner !== window) {
    owner = window;
    controller = new AbortController();
    const current = controller;
    window.addEventListener('pagehide', event => {
      // A bfcache entry is frozen and can resume; it is not discarded.
      if (!event.persisted) current.abort();
    });
  }

  return controller?.signal;
}
