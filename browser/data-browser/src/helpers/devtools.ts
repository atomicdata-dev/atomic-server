/**
 * Console-accessible diagnostics. Attached to `window.devtools` in dev mode.
 *
 * Goal: inspect a resource across every persistence layer (server, JS store,
 * WASM ClientDb / OPFS) and tail the WebSocket / commit log without having
 * to hand-roll probes in DevTools each time.
 *
 * All methods log a structured object and also return it, so you can assign
 * the result to a variable for further inspection.
 */
import type { Store, CommitLogEntry, Resource } from '@tomic/react';
import {
  ATOMIC_PREFIX,
  canonicalizeScheme,
  constraintViolations,
  type ConstraintViolation,
} from '@tomic/lib';

type InspectResult = {
  subject: string;
  jsStore: {
    present: boolean;
    loading?: boolean;
    new?: boolean;
    error?: string;
    lastCommit?: string;
    propCount?: number;
    props?: Record<string, unknown>;
  };
  wasm: {
    hasClientDb: boolean;
    ready?: boolean;
    jsonAd?: string | null;
    jsonAdChars?: number;
    hasLoroSnapshot?: boolean;
    loroSnapshotBytes?: number;
    threw?: string;
  };
  server: {
    connected: boolean;
    httpStatus?: number;
    jsonAd?: unknown;
    error?: string;
  };
  /** Values breaking their classes' constraints (loaded classes only). */
  violations: ConstraintViolation[];
};

function summarizeResource(r: Resource | undefined): InspectResult['jsStore'] {
  if (!r) return { present: false };
  const props: Record<string, unknown> = {};
  let count = 0;

  for (const [k, v] of r.getEntries()) {
    // Binary (loroUpdate) shown as length, not payload — too noisy otherwise.
    props[k] = v instanceof Uint8Array ? `<Uint8Array ${v.byteLength}b>` : v;
    count++;
  }

  return {
    present: true,
    loading: r.loading,
    new: r.new,
    error: r.error?.message,
    lastCommit:
      (r.get('https://atomicdata.dev/properties/lastCommit') as string) ??
      undefined,
    propCount: count,
    props,
  };
}

async function fetchFromServer(
  store: Store,
  subject: string,
): Promise<InspectResult['server']> {
  const connected = store.getSyncStatus().serverConnected;
  if (!connected) return { connected: false };

  // Only HTTP(S) subjects can be hit with fetch. did:/internal: live on the
  // server by logical subject lookup, not URL fetch — skip them.
  if (!/^https?:/.test(subject)) {
    return {
      connected: true,
      error: `not fetchable (scheme in ${subject.slice(0, 20)}…)`,
    };
  }

  try {
    const res = await fetch(subject, {
      headers: { Accept: 'application/ad+json' },
    });
    const body = await res.text();
    let parsed: unknown = body;

    try {
      parsed = JSON.parse(body);
    } catch {
      /* leave as string */
    }

    return { connected: true, httpStatus: res.status, jsonAd: parsed };
  } catch (e) {
    return {
      connected: true,
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

async function inspectWasm(
  store: Store,
  subject: string,
): Promise<InspectResult['wasm']> {
  const clientDb = store.getClientDb();
  if (!clientDb) return { hasClientDb: false };
  const out: InspectResult['wasm'] = {
    hasClientDb: true,
    ready: clientDb.isReady,
  };

  try {
    const jsonAd = await clientDb.getResource(subject);
    out.jsonAd = jsonAd;
    out.jsonAdChars = typeof jsonAd === 'string' ? jsonAd.length : 0;
    const snap = await clientDb.getLoroSnapshot(subject);
    out.hasLoroSnapshot = !!snap;
    out.loroSnapshotBytes = snap?.byteLength ?? 0;
  } catch (e) {
    out.threw = e instanceof Error ? e.message : String(e);
  }

  return out;
}

/**
 * Resolve the default subject: `?subject=...` in the URL, falling back to
 * the full URL for non-`/app/*` paths, and finally to the active drive
 * (server URL if no drive has been selected — devtools is a debugging
 * helper, so a sensible fallback is more useful than `undefined`).
 */
function currentSubject(store: Store): string {
  if (typeof window === 'undefined')
    return store.getDrive() ?? store.getServerUrl();
  const params = new URLSearchParams(window.location.search);
  const q = params.get('subject');
  if (q) return q;

  if (!window.location.pathname.startsWith('/app/')) {
    return window.location.href;
  }

  return store.getDrive() ?? store.getServerUrl();
}

/** Inspect one subject across all three persistence layers. */
export async function inspect(
  store: Store,
  subjectRaw?: string,
): Promise<InspectResult> {
  const subject = subjectRaw ?? currentSubject(store);
  const jsStore = summarizeResource(store.resources.get(subject));
  const [wasm, server] = await Promise.all([
    inspectWasm(store, subject),
    fetchFromServer(store, subject),
  ]);

  const local = store.resources.get(subject);

  const lookup = (s: string) => {
    const r =
      store.resources.get(s) ?? store.resources.get(canonicalizeScheme(s));

    return r?.isReady() ? r : undefined;
  };

  const violations = local?.isReady()
    ? constraintViolations(lookup, local)
    : [];

  const result: InspectResult = { subject, jsStore, wasm, server, violations };
  const serverSummary = !server.connected
    ? 'offline'
    : server.error
      ? `error: ${server.error}`
      : `HTTP ${server.httpStatus}`;
  console.log(
    `[devtools.inspect] ${subject.slice(0, 60)}
  jsStore: present=${jsStore.present} loading=${jsStore.loading ?? '-'} new=${jsStore.new ?? '-'} props=${jsStore.propCount ?? 0} error=${jsStore.error ?? '-'}
  wasm:    clientDb=${wasm.hasClientDb} ready=${wasm.ready ?? '-'} jsonAd=${wasm.jsonAdChars ?? 0}ch snapshot=${wasm.hasLoroSnapshot ?? '-'}${wasm.threw ? ' threw=' + wasm.threw : ''}
  server:  ${serverSummary}
  violations: ${violations.length}${violations.map(v => '\n    ' + v.message).join('')}`,
    result,
  );

  return result;
}

/** List identifier subjects in the WASM DB. Pass a prefix to narrow; the
 *  default matches the canonical `atomic:` keys the on-open migration leaves. */
export async function opfsList(
  store: Store,
  prefix = ATOMIC_PREFIX,
): Promise<string[]> {
  const clientDb = store.getClientDb();

  if (!clientDb) {
    console.warn('[devtools.opfsList] no clientDb');

    return [];
  }

  const all = await clientDb.allSubjects();
  const filtered = all.filter(s => s.startsWith(prefix));
  console.log(
    `[devtools.opfsList] ${filtered.length}/${all.length} subjects matching "${prefix}"`,
    filtered,
  );

  return filtered;
}

/** Tail the commit log. Most recent N (default 20), with direction/status. */
export function wsLog(store: Store, n = 20): CommitLogEntry[] {
  const log = store.getCommitLog().slice(-n);
  console.table(
    log.map(e => ({
      when: new Date(e.timestamp).toISOString().slice(11, 23),
      dir: e.direction,
      status: e.status,
      subject: e.subject?.slice(0, 60),
      commit: (e.commitId ?? '').slice(-12),
      loro: e.hasLoroUpdate ? 'Y' : '',
      destroy: e.destroy ? 'Y' : '',
      summary: e.summary,
    })),
  );

  return log;
}

/** Dump every resource in the JS store that is loading, errored, or new. */
export function problems(store: Store): unknown[] {
  const out: unknown[] = [];

  for (const [subject, r] of store.resources.entries()) {
    if (r.loading || r.error || r.new) {
      out.push({
        subject: subject.slice(0, 80),
        loading: r.loading,
        new: r.new,
        error: r.error?.message,
      });
    }
  }

  console.table(out);

  return out;
}

/** Force-put the current JS-store state of a subject into the WASM DB. */
export async function forcePut(store: Store, subject: string): Promise<void> {
  const clientDb = store.getClientDb();
  if (!clientDb) throw new Error('no clientDb');
  const r = store.resources.get(subject);
  if (!r) throw new Error(`not in js store: ${subject}`);
  const obj: Record<string, unknown> = { '@id': subject };

  for (const [k, v] of r.getEntries()) {
    if (v instanceof Uint8Array) continue;
    obj[k] = v;
  }

  const jsonAd = JSON.stringify(obj);
  console.log(`[devtools.forcePut] putting ${subject.slice(0, 60)}`, {
    chars: jsonAd.length,
  });
  await clientDb.putResource(jsonAd);
  const back = await clientDb.getResource(subject);
  console.log(
    `[devtools.forcePut] verified:`,
    back
      ? `YES (${back.length} chars)`
      : 'NO (put returned but getResource is null)',
  );
}

export function attachDevtools(store: Store): void {
  const api = {
    store,
    inspect: (s?: string) => inspect(store, s),
    opfsList: (prefix?: string) => opfsList(store, prefix),
    wsLog: (n?: number) => wsLog(store, n),
    problems: () => problems(store),
    forcePut: (s: string) => forcePut(store, s),
    help: () => {
      console.log(
        [
          'devtools.inspect(subject?)   — resource state in JS store, WASM/OPFS, and server',
          'devtools.opfsList(prefix?)   — subjects in WASM DB (default prefix: did:ad:)',
          'devtools.wsLog(n?)           — last N commit log entries as a table',
          'devtools.problems()          — resources that are loading, errored, or new',
          'devtools.forcePut(subject)   — re-put a JS-store resource to OPFS and verify',
        ].join('\n'),
      );
    },
  };
  (window as unknown as { devtools: typeof api }).devtools = api;
}
