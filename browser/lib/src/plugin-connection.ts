import { signRequest } from './authentication.js';
import type { Store } from './store.js';
import type { PluginManifest } from './plugin-manifest.js';

export interface PluginRelease {
  source: string;
  manifest: PluginManifest;
  runtime: string;
  schemas: Record<string, string>;
}
export interface ExternalIntent {
  /** Stable within this run. Reuse it for retry/status, never for another payload. */
  id: string;
  operation: string;
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
}
export interface ExternalReceipt {
  status: number;
  body: string;
}
export interface PluginTarget {
  drive: string;
  plugin: string;
}
type ConnectionStore = Pick<Store, 'getAgent' | 'getServerUrl'>;

async function post<T>(
  store: ConnectionStore,
  path: string,
  body: unknown,
  transport: typeof fetch,
): Promise<T> {
  const agent = store.getAgent();
  if (!agent) throw new Error('sign in before changing a plugin connection');
  const url = `${store.getServerUrl()}${path}`;
  const response = await transport(url, {
    method: 'POST',
    headers: {
      ...(await signRequest(url, agent, {})),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(await response.text());

  return response.json() as Promise<T>;
}

export function publishPluginRelease(
  store: ConnectionStore,
  target: PluginTarget & {
    schemas?: Record<string, string>;
    domains?: string[];
    standards?: string[];
  },
  transport: typeof fetch = fetch,
): Promise<{ id: string; release: PluginRelease }> {
  return post(store, '/plugin-release', target, transport);
}

/** Host-side approval API. Never expose this function to a preview interpreter.
 * Transport errors are deliberately not retried: the server's receipt must
 * determine whether the remote operation already happened. */
export function approveExternalIntent(
  store: ConnectionStore,
  approval: PluginTarget & {
    release: string;
    run: string;
    intent: ExternalIntent;
  },
  transport: typeof fetch = fetch,
): Promise<ExternalReceipt> {
  return post(store, '/plugin-external-apply', approval, transport);
}

export interface ExternalOperation extends PluginTarget {
  release: string;
  run: string;
  intent: string;
}
export interface ExternalOperationStatus {
  intent: ExternalIntent;
  receipt: ExternalReceipt | null;
  resolution: { actor: string; evidence: string; at: number } | null;
}

/** Read the durable result before deciding how to recover a transport failure. */
export function inspectExternalOperation(
  store: ConnectionStore,
  operation: ExternalOperation,
  transport: typeof fetch = fetch,
): Promise<ExternalOperationStatus | null> {
  return post(store, '/plugin-external-status', operation, transport);
}

/** Operator-only assertion after checking the provider. This does not resend a write. */
export function confirmExternalOperation(
  store: ConnectionStore,
  operation: ExternalOperation,
  receipt: ExternalReceipt,
  evidence: string,
  transport: typeof fetch = fetch,
): Promise<{ resolved: true }> {
  return post(
    store,
    '/plugin-external-confirm',
    { operation, receipt, evidence },
    transport,
  );
}

export interface ConnectionState {
  revision: number;
  records: Record<
    string,
    { local: string; baseline: Record<string, unknown> | null }
  >;
  cursor: unknown;
}
export interface ConnectionCheckpoint {
  revision: number;
  records: Array<{
    remote: string;
    local: string;
    local_projection: Record<string, unknown> | null;
    remote_projection: Record<string, unknown> | null;
  }>;
  cursor: unknown;
}
export function readConnectionState(
  store: ConnectionStore,
  target: PluginTarget,
  transport: typeof fetch = fetch,
): Promise<ConnectionState> {
  return post(store, '/plugin-connection-state', target, transport);
}
/** Persist only acknowledged results. Stale revisions require a fresh read and reconciliation. */
export function checkpointConnection(
  store: ConnectionStore,
  target: PluginTarget,
  checkpoint: ConnectionCheckpoint,
  transport: typeof fetch = fetch,
): Promise<ConnectionState> {
  return post(
    store,
    '/plugin-connection-checkpoint',
    { target, checkpoint },
    transport,
  );
}

/** Pin a private connection package without publishing it to the catalog. */
export function pinPluginRelease(
  store: ConnectionStore,
  target: PluginTarget,
  transport: typeof fetch = fetch,
): Promise<{ id: string; release: PluginRelease }> {
  return post(store, '/plugin-release-pin', target, transport);
}

/** Host acquisition with credentials kept on the server and release-scoped egress. */
export function readExternalOperation(
  store: ConnectionStore,
  request: PluginTarget & {
    release: string;
    run: string;
    intent: ExternalIntent;
  },
  transport: typeof fetch = fetch,
): Promise<ExternalReceipt> {
  return post(store, '/plugin-external-read', request, transport);
}

/** Complete server-authoritative membership for sync. Unlike UI collections,
 * failures and incomplete pages must never masquerade as an empty collection. */
export async function readConnectionSubjects(
  store: Pick<Store, 'getServerUrl' | 'fetchResourceFromServer'>,
  drive: string,
  property?: string,
  value?: string,
): Promise<string[]> {
  const { collections } = await import('./ontologies/collections.js');
  const { enableLoro } = await import('./loro-loader.js');
  await enableLoro();
  const subjects = new Set<string>();
  let expected: number | undefined;

  for (let page = 0; page < 100; page++) {
    const url = new URL('/query', store.getServerUrl());
    for (const [key, val] of Object.entries({
      drive,
      ...(property === undefined ? {} : { property }),
      ...(value === undefined ? {} : { value }),
      page_size: '100',
      current_page: String(page),
      include_nested: 'false',
    }))
      url.searchParams.set(key, val);
    const resource = await store.fetchResourceFromServer(url.toString(), {
      noWebSocket: true,
      // Query results are generated snapshots, not editable CRDT documents.
      // Merging successive snapshots can retain old members beside a new count.
      forceOverride: true,
    });
    if (resource.error)
      throw new Error(
        'Connection query failed; refusing to infer an empty collection',
      );
    resource.getLoroDoc();
    const total = resource.get(collections.properties.totalMembers);
    const members = resource.get(collections.properties.members);
    if (
      typeof total !== 'number' ||
      !Number.isSafeInteger(total) ||
      total < 0 ||
      !Array.isArray(members) ||
      members.some(m => typeof m !== 'string')
    )
      throw new Error('Invalid connection query response');
    if (expected !== undefined && expected !== total)
      throw new Error(
        'Connection membership changed during pagination; preview again',
      );
    expected = total;
    for (const subject of members as string[]) subjects.add(subject);
    if (subjects.size === total) return [...subjects];
    if (subjects.size > total || members.length === 0)
      throw new Error('Incomplete connection query response');
  }

  throw new Error('Connection query exceeds the 10,000 resource pilot limit');
}

/** Server-saved sandbox continuation. Approval is bound to run and release. */
export interface PluginSyncSession {
  run: string;
  release: string;
  config: unknown;
  proposal: unknown;
  problems: Array<{ severity: 'error' | 'warning'; message: string }>;
  status: 'preview' | 'running' | 'error' | 'complete';
  error: string | null;
  approved_by: string | null;
  pending?: {
    effect: { kind: string; id: string; request?: ExternalIntent };
  } | null;
}
export function previewPluginSync(
  store: ConnectionStore,
  target: PluginTarget & { release: string; config: unknown },
  transport: typeof fetch = fetch,
): Promise<PluginSyncSession> {
  return post(store, '/plugin-sync-preview', target, transport);
}
export function applyPluginSync(
  store: ConnectionStore,
  target: PluginTarget & { run: string },
  transport: typeof fetch = fetch,
): Promise<PluginSyncSession> {
  return post(store, '/plugin-sync-apply', target, transport);
}
export function getPluginSync(
  store: ConnectionStore,
  target: PluginTarget,
  transport: typeof fetch = fetch,
): Promise<PluginSyncSession | null> {
  return post(store, '/plugin-sync-status', target, transport);
}

export interface PluginSyncSchedule {
  interval_seconds: number;
  next_at: number;
  error: string | null;
}
export function pluginSyncSchedule(
  store: ConnectionStore,
  target: PluginTarget & { run: string; interval_seconds?: number },
  transport: typeof fetch = fetch,
): Promise<PluginSyncSchedule | null> {
  return post(store, '/plugin-sync-schedule', target, transport);
}
