const asked = new Map<string, Promise<boolean>>();

/** A plain request has no timeout of its own, so a server that never answers
 *  would keep the page's network busy for minutes. The store gives up on its
 *  own requests after ten seconds, so this must not outlast that. */
const PROBE_TIMEOUT_MS = 5_000;

/**
 * Whether the server at `serverUrl` has a `/conversations` endpoint. A server
 * without one answers with its 404, or with a page of HTML (a dev server or
 * a static host that falls back to `index.html`). Asking the store for such a
 * URL logs a console error for every failed parse, which a page-level check
 * (the saas portal e2e) counts as a failure, so this asks with a plain
 * request first, once per server.
 *
 * Anything that is not clearly "no endpoint" counts as one: a 401 for an
 * unsigned request is the endpoint asking for a signature, and a network
 * error is not a reason to stop asking later.
 */
export function hasConversationsEndpoint(
  serverUrl: string,
  path: string,
): Promise<boolean> {
  const url = `${serverUrl}${path}`;
  let known = asked.get(url);

  if (!known) {
    known = probe(url).catch(() => {
      // Could not ask, so do not remember an answer.
      asked.delete(url);

      return true;
    });
    asked.set(url, known);
  }

  return known;
}

async function probe(url: string): Promise<boolean> {
  const response = await fetch(url, {
    headers: { Accept: 'application/ad+json' },
    signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
  });
  const type = response.headers.get('content-type') ?? '';

  return response.status !== 404 && !type.includes('text/html');
}

/** Forget what was learned about servers. For tests. */
export function resetConversationsEndpointCache(): void {
  asked.clear();
}
