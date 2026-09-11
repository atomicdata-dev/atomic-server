// Deep links (atomic:…) reach the webview as 'atomic-deep-link' DOM events,
// dispatched by the Tauri shell (desktop/src/lib.rs). This module's listener
// is registered at module scope from the app entry — before React mounts — so
// a link that launched the app (system camera scanning a pairing QR) is
// queued rather than lost. `PairingLinkHandler` installs the sink and drains
// the queue once the UI is ready.
//
// Delivery from the shell is at-least-once: an eval into a page that hasn't
// loaded yet is silently lost (and Android has no reliable page-ready
// callback), so the shell re-dispatches pending links for a while. The
// seen-set makes each link handled exactly once per page.

const queue: string[] = [];
const seen = new Set<string>();
let sink: ((uri: string) => void) | undefined;

if (typeof window !== 'undefined') {
  window.addEventListener('atomic-deep-link', event => {
    const uri = (event as CustomEvent).detail;

    if (typeof uri !== 'string' || seen.has(uri)) {
      return;
    }

    seen.add(uri);

    if (sink) {
      sink(uri);
    } else {
      queue.push(uri);
    }
  });
}

/** Install the live handler and immediately drain anything that arrived early. */
export function setDeepLinkSink(handler: (uri: string) => void): void {
  sink = handler;
  queue.splice(0).forEach(handler);
}

/**
 * Feed a pairing link into the same pipeline a scanned deep link takes —
 * used by in-app entry points (the Pair dialog's paste field). Clears the
 * seen-set first so an explicit user action always re-processes the code.
 */
export function deliverDeepLink(uri: string): void {
  seen.delete(uri);
  window.dispatchEvent(new CustomEvent('atomic-deep-link', { detail: uri }));
}

export function clearDeepLinkSink(handler: (uri: string) => void): void {
  if (sink === handler) {
    sink = undefined;
  }
}
