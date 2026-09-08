/** One host API for the UI, Atomic assistant and MCP hosts. */
import { signRequest } from './authentication.js';
import type { Store } from './store.js';
import type { DeclaredAction } from './plugin-manifest.js';
import type {
  ExternalIntent,
  ExternalReceipt,
  PluginTarget,
} from './plugin-connection.js';

export type ActionStore = Pick<Store, 'getAgent' | 'getServerUrl'>;
export interface IntegrationTool {
  name: string;
  title: string;
  description: string;
  inputSchema: DeclaredAction['inputSchema'];
  annotations: { readOnlyHint: boolean; openWorldHint: boolean };
}
export interface ActionProposal {
  archived?: { at: number; state: string; payload_hash: string };
  origin?: { caller: string; source_hash: string };
  id: string;
  action: string;
  title: string;
  arguments: Record<string, unknown>;
  created_at: number;
  release: string;
  intent: ExternalIntent;
}
export type ActionResult =
  | { status: 'read' | 'completed'; result: ExternalReceipt }
  | { status: 'needs_review'; proposal: ActionProposal };

async function post<T>(
  store: ActionStore,
  endpoint: string,
  body: unknown,
): Promise<T> {
  const agent = store.getAgent();
  if (!agent) throw new Error('Sign in to use an integration');
  const url = `${store.getServerUrl()}/${endpoint}`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      ...(await signRequest(url, agent, {})),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(await response.text());

  return response.json();
}

export function listIntegrationActions(
  store: ActionStore,
  target: PluginTarget,
) {
  return post<{ release: string; tools: IntegrationTool[] }>(
    store,
    'integration-actions',
    target,
  );
}
export function callIntegrationAction(
  store: ActionStore,
  target: PluginTarget,
  action: string,
  args: Record<string, unknown>,
  id: string,
) {
  return post<ActionResult>(store, 'integration-action-call', {
    ...target,
    call: { action, arguments: args, id },
  });
}
export function integrationActionProposals(
  store: ActionStore,
  target: PluginTarget,
) {
  return post<ActionProposal[]>(store, 'integration-action-proposals', target);
}
export function approveIntegrationAction(
  store: ActionStore,
  target: PluginTarget,
  id: string,
) {
  return post<ExternalReceipt>(store, 'integration-action-approve', {
    ...target,
    id,
  });
}

/** MCP tools/list and tools/call adapter; an MCP host supplies transport/auth.
 * Deliberately exposes no approval tool. Write calls return proposals for Atomic UI review.
 */
export function integrationMcpAdapter(
  store: ActionStore,
  target: PluginTarget,
) {
  return {
    listTools: async () => ({
      tools: (await listIntegrationActions(store, target)).tools,
    }),
    callTool: async ({
      name,
      arguments: args = {},
      _meta,
    }: {
      name: string;
      arguments?: Record<string, unknown>;
      _meta?: Record<string, unknown>;
    }) => {
      try {
        const id =
          typeof _meta?.['atomic/callId'] === 'string'
            ? _meta['atomic/callId']
            : crypto.randomUUID();
        const result = await callIntegrationAction(
          store,
          target,
          name,
          args,
          id,
        );

        return {
          content: [{ type: 'text' as const, text: JSON.stringify(result) }],
          structuredContent: result,
          isError: false,
        };
      } catch (e) {
        return {
          content: [{ type: 'text' as const, text: String(e) }],
          isError: true,
        };
      }
    },
  };
}

export interface ActionHistoryEntry {
  proposal: ActionProposal;
  state:
    | 'pending'
    | 'completed'
    | 'failed'
    | 'uncertain'
    | 'expired'
    | 'cancelled'
    | 'stale';
  receipt: ExternalReceipt | null;
  resolution: { actor: string; evidence: string; at: number } | null;
}
export interface ActionGrant {
  origin: { caller: string; source_hash: string };
  action: string;
  mode: 'review' | 'automatic';
  expires_at: number;
  release: string;
}
export function integrationActionHistory(
  store: ActionStore,
  target: PluginTarget,
) {
  return post<ActionHistoryEntry[]>(
    store,
    'integration-action-history',
    target,
  );
}
export interface ActionHistoryPage {
  entries: ActionHistoryEntry[];
  nextCursor: string | null;
}
export function integrationActionHistoryPage(
  store: ActionStore,
  target: PluginTarget,
  cursor?: string,
) {
  return post<ActionHistoryPage>(store, 'integration-action-history', {
    ...target,
    limit: 50,
    ...(cursor ? { cursor } : {}),
  });
}
export function cancelIntegrationAction(
  store: ActionStore,
  target: PluginTarget,
  id: string,
) {
  return post<boolean>(store, 'integration-action-cancel', { ...target, id });
}
export function integrationActionGrants(
  store: ActionStore,
  target: PluginTarget,
) {
  return post<ActionGrant[]>(store, 'integration-action-grants', target);
}
export function setIntegrationActionGrant(
  store: ActionStore,
  target: PluginTarget,
  caller: string,
  action: string,
  mode: 'review' | 'automatic' | 'revoke',
) {
  return post<boolean>(store, 'integration-action-grant', {
    ...target,
    caller,
    action,
    mode,
  });
}
export function inspectActionRecovery(
  store: ActionStore,
  target: PluginTarget,
  id: string,
  action: string,
  args: Record<string, unknown>,
  evidence: string,
) {
  return post<{ receipt: ExternalReceipt }>(
    store,
    'integration-action-recovery-inspect',
    {
      ...target,
      id,
      call: { id: crypto.randomUUID(), action, arguments: args },
      evidence,
    },
  );
}
export function confirmActionRecovery(
  store: ActionStore,
  target: PluginTarget,
  id: string,
) {
  return post<boolean>(store, 'integration-action-recovery-confirm', {
    ...target,
    id,
  });
}

export interface ActionCompactionPage {
  scanned: number;
  eligible: number;
  compacted: number;
  reclaimableBytes: number;
  nextCursor: string | null;
}
export function compactIntegrationActionHistory(
  store: ActionStore,
  target: PluginTarget,
  options: {
    cursor?: string;
    apply?: boolean;
    includeCompleted?: boolean;
    includeAutomation?: boolean;
  } = {},
) {
  return post<ActionCompactionPage>(
    store,
    'integration-action-history-compact',
    {
      ...target,
      ...options,
    },
  );
}

export interface ActionConsumer {
  run: string;
  state: 'unfinished' | 'completed' | 'abandoned';
  audit: {
    at: number;
    actor?: string;
    reason?: string;
    summary?: string;
  } | null;
}
export function integrationActionConsumers(
  store: ActionStore,
  target: PluginTarget,
  id: string,
) {
  return post<ActionConsumer[]>(store, 'integration-action-consumers', {
    ...target,
    id,
  });
}
export function abandonIntegrationConsumer(
  store: ActionStore,
  target: PluginTarget,
  id: string,
  run: string,
  reason: string,
) {
  return post<boolean>(store, 'integration-action-consumer-abandon', {
    ...target,
    id,
    run,
    reason,
  });
}
