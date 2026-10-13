import { serverProps } from './serverOntology';

/**
 * What an address turned out to be.
 *  - `node`: it answered `/server` like an AtomicServer.
 *  - `not-node`: it answered, but with something else (a website's HTML, a 404).
 *  - `unreachable`: no answer at all (DNS, refused, offline, timeout).
 */
export type ServerProbe = 'node' | 'not-node' | 'unreachable';

/**
 * Ask `serverUrl` whether it is an AtomicServer before it is added.
 *
 * Reads the same `GET /server` document `fetchManagedInfo` reads (the old
 * `/node-info` is gone). A node reports its version or node id there; a site
 * that serves its HTML for every path answers 200 text/html, which fails JSON
 * parsing and so counts as `not-node`.
 */
export async function probeServer(
  serverUrl: string,
  timeoutMs = 5000,
): Promise<ServerProbe> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(new URL('/server', serverUrl).toString(), {
      headers: { Accept: 'application/ad+json' },
      credentials: 'omit',
      // An address that redirects is not the node the person typed (or the
      // one a record named); a redirect can lead anywhere.
      redirect: 'error',
      signal: controller.signal,
    });

    if (!res.ok) return 'not-node';

    let data: unknown;

    try {
      data = await res.json();
    } catch {
      return 'not-node';
    }

    const record = data as Record<string, unknown> | null;
    const isNode =
      typeof record === 'object' &&
      record !== null &&
      Boolean(record[serverProps.version] || record[serverProps.nodeId]);

    return isNode ? 'node' : 'not-node';
  } catch {
    return 'unreachable';
  } finally {
    clearTimeout(timer);
  }
}
