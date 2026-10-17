import { isRunningInTauri } from './tauri';
import { isHostedDistribution } from './managedServer';
import { serverProps } from './serverOntology';

/**
 * Is the origin this app was served from an atomic-server?
 *
 * Usually yes: a node serves its own data-browser, and `window.location.origin`
 * is the server. The managed deployment breaks that: it serves the very same
 * SPA from a shared origin (`app.atomicserver.eu`) that is the portal's
 * process, not a node. Someone on the free tier has no node at all — their
 * workspace lives in this browser (OPFS) and in Cloud Vault — yet the store
 * still needs *some* `serverUrl`, and defaulting to the origin made the app
 * treat a static host as its server: a WebSocket retried forever with a toast
 * per attempt, `/server` polled for a JSON document that came back as
 * index.html, every commit parked in the outbox, and the Sync page insisting
 * the workspace "already lives on app.atomicserver.eu".
 *
 * So the hosted build asks once, at boot, before the Store exists. The answer
 * is kept here so later code can tell "no server" from "server offline"
 * without a second round trip.
 */

let originWithoutNode: string | undefined;

/** Origin (no trailing slash) as `new URL(...).origin` would give it. */
function originOf(url: string): string | undefined {
  try {
    return new URL(url).origin;
  } catch {
    return undefined;
  }
}

/**
 * True when `url` points at the origin that was probed and found to run no
 * atomic-server. False for every other URL, including one never probed.
 */
export function isOriginWithoutNode(url: string | undefined): boolean {
  if (!url || !originWithoutNode) return false;

  return originOf(url) === originWithoutNode;
}

const MEMO_KEY = 'atomic.originProbe';

type Answer = 'node' | 'none';

function readMemo(origin: string): Answer | undefined {
  try {
    const memo = JSON.parse(localStorage.getItem(MEMO_KEY) ?? '{}');
    const answer = memo[origin];

    return answer === 'node' || answer === 'none' ? answer : undefined;
  } catch {
    return undefined;
  }
}

function writeMemo(origin: string, answer: Answer): void {
  try {
    const memo = JSON.parse(localStorage.getItem(MEMO_KEY) ?? '{}');
    localStorage.setItem(
      MEMO_KEY,
      JSON.stringify({ ...memo, [origin]: answer }),
    );
  } catch {
    // Without storage every boot waits for the probe, as it always did.
  }
}

/**
 * Apply the answer from the last visit, if there is one, so boot does not
 * have to wait for the probe. Why trust it: a deployment's origin is either
 * the portal or a node for as long as anyone uses it, and the probe runs again
 * in the background on every boot and corrects the memo (and, once it is
 * known, the in-memory answer). A wrong memo costs one boot with the old
 * answer, never a stuck state. The first visit has no memo and waits, exactly
 * as before. Returns whether a memo was applied.
 */
export function recallOriginProbe(origin: string): boolean {
  const answer = readMemo(origin);

  if (!answer) return false;

  rememberOriginWithoutNode(answer === 'none' ? origin : undefined);

  return true;
}

/** Only in tests. Boot sets this through {@link probeOriginForNode}. */
export function rememberOriginWithoutNode(origin: string | undefined): void {
  originWithoutNode = origin ? originOf(origin) : undefined;
}

/**
 * Whether this build should probe its own origin at all.
 *
 * Only the hosted distribution is ever served by a non-node — a source build
 * comes out of an atomic-server, so asking would only delay its boot. The
 * desktop shell has no HTTP origin to ask about (`tauri://localhost`).
 */
export function originMayLackNode(): boolean {
  return isHostedDistribution() && !isRunningInTauri();
}

function concludeNone(origin: string): void {
  rememberOriginWithoutNode(origin);
  writeMemo(origin, 'none');
}

function concludeNode(origin: string): void {
  if (isOriginWithoutNode(origin)) rememberOriginWithoutNode(undefined);
  writeMemo(origin, 'node');
}

/**
 * Ask `origin` whether it is an atomic-server, remembering a "no".
 *
 * A node answers `/server` with a JSON `Server` resource carrying its version
 * (see `fetchManagedInfo`); a static host serves the SPA's index.html for
 * that path, or a 404. Both are a definite no.
 *
 * Only a definite answer changes anything: a probe that fails outright
 * (offline, timeout) leaves the default in place, so a node-served install
 * reopened offline still tries to reconnect the way it always has.
 */
export async function probeOriginForNode(
  origin: string,
  timeoutMs = 3000,
): Promise<void> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(new URL('/server', origin).toString(), {
      headers: { Accept: 'application/ad+json' },
      signal: controller.signal,
    });

    if (res.status === 404) {
      concludeNone(origin);

      return;
    }

    if (!res.ok) return;

    let data: unknown;

    try {
      data = await res.json();
    } catch {
      // index.html, not JSON.
      concludeNone(origin);

      return;
    }

    const version = (data as Record<string, unknown> | null)?.[
      serverProps.version
    ];
    const nodeId = (data as Record<string, unknown> | null)?.[
      serverProps.nodeId
    ];

    if (!version && !nodeId) {
      concludeNone(origin);
    } else {
      concludeNode(origin);
    }
  } catch {
    // No answer is not a "no".
  } finally {
    clearTimeout(timer);
  }
}
