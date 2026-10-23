import { core } from '@tomic/react';
import { withDeadline } from '../withDeadline';
import { PRODUCT_NAME } from './product';
import {
  clearManagedAccountBinding,
  readManagedAccountBinding,
} from './binding';
import {
  getManagedEnrollments,
  type ManagedEnrollmentSummary,
} from './enrollmentApi';
import { hasManagedApi, managedFetch } from './api';
import { getRecoverySecret, sameAgent } from './recovery';
import { getManagedAccount, type ManagedAccount } from './session';

export type IdentityMismatchReason =
  | 'recovery_agent'
  | 'enrollment_agent'
  | 'binding_agent'
  | 'stale_local_agent';

export type IdentityReconcileIssue = {
  managedAccountEmail: string;
  localAgentSubject: string | null;
  expectedAgentSubject: string | null;
  reason: IdentityMismatchReason;
};

export type IdentityReconcileResult =
  | { ok: true; managedAccount: ManagedAccount | null }
  | { ok: false; issue: IdentityReconcileIssue };

function activeEnrollmentAgents(
  enrollments: ManagedEnrollmentSummary[],
): string[] {
  const agents: string[] = [];

  for (const enrollment of enrollments) {
    if (enrollment.status === 'Disabled') continue;

    const subject = enrollment.agent_subject;

    if (subject && !agents.some(agent => sameAgent(agent, subject))) {
      agents.push(subject);
    }
  }

  return agents;
}

/**
 * Returns whether the local Atomic agent aligns with the signed-in Managed Sync
 * account. When there is no Managed session, always ok (self-hosted / local-only).
 */
export async function evaluateIdentityReconciliation(
  localAgentSubject: string | undefined,
): Promise<IdentityReconcileResult> {
  const managedAccount = await getManagedAccount().catch(() => null);

  if (!managedAccount) {
    return { ok: true, managedAccount: null };
  }

  const [recovery, enrollments] = await Promise.all([
    getRecoverySecret().catch(() => null),
    getManagedEnrollments().catch(() => [] as ManagedEnrollmentSummary[]),
  ]);

  const binding = readManagedAccountBinding();
  const bindingAgent =
    binding?.owner_email === managedAccount.email
      ? binding.expected_agent_subject
      : null;

  if (binding && binding.owner_email !== managedAccount.email) {
    clearManagedAccountBinding();
  }

  const enrollmentAgents = activeEnrollmentAgents(enrollments);
  const recoveryAgent = recovery?.agent_subject ?? null;

  if (!localAgentSubject) {
    return { ok: true, managedAccount };
  }

  if (recoveryAgent && !sameAgent(recoveryAgent, localAgentSubject)) {
    return {
      ok: false,
      issue: {
        managedAccountEmail: managedAccount.email,
        localAgentSubject,
        expectedAgentSubject: recoveryAgent,
        reason: 'recovery_agent',
      },
    };
  }

  if (
    enrollmentAgents.length > 0 &&
    !enrollmentAgents.some(agent => sameAgent(agent, localAgentSubject))
  ) {
    return {
      ok: false,
      issue: {
        managedAccountEmail: managedAccount.email,
        localAgentSubject,
        expectedAgentSubject: enrollmentAgents[0] ?? null,
        reason: 'enrollment_agent',
      },
    };
  }

  if (bindingAgent && !sameAgent(bindingAgent, localAgentSubject)) {
    return {
      ok: false,
      issue: {
        managedAccountEmail: managedAccount.email,
        localAgentSubject,
        expectedAgentSubject: bindingAgent,
        reason: 'binding_agent',
      },
    };
  }

  if (
    !recoveryAgent &&
    enrollmentAgents.length === 0 &&
    !bindingAgent &&
    localAgentSubject
  ) {
    return {
      ok: false,
      issue: {
        managedAccountEmail: managedAccount.email,
        localAgentSubject,
        expectedAgentSubject: null,
        reason: 'stale_local_agent',
      },
    };
  }

  return { ok: true, managedAccount };
}

export type ServerReconcileResult =
  | { ok: true }
  | { ok: false; expectedOrigin: string };

/**
 * Returns the node actually hosting the active drive: per the signed-in
 * account's enrollments, else per the control plane's answer for the drive
 * itself. Undefined when neither knows (self-hosted, local-only, or no
 * control plane).
 *
 * This exists because `serverUrl` is a single client-side setting (see
 * `Store.setServerUrl`) that isn't derived from a drive's `did:` subject —
 * once the app is served from a fixed origin instead of the node's own
 * domain, nothing else keeps it pointed at the right node across a fresh
 * device (no stored value yet) or a drive migration (stored value goes
 * stale). `enrollment.http_origin` is the source of truth for "where does
 * this drive actually live right now."
 */
async function resolveHostedDriveOrigin(
  currentDriveSubject: string | undefined,
): Promise<string | undefined> {
  const fromAccount = await accountHostedDriveOrigin(currentDriveSubject);

  if (fromAccount) return fromAccount;

  // Hosting belongs to the drive, not to whoever pays for it: a member of a
  // drive someone else hosts has no enrollment of their own, and neither does
  // a device that is not signed in to the account yet. Ask about the drive.
  return currentDriveSubject
    ? driveHostedOrigin(currentDriveSubject)
    : undefined;
}

/** The node this account's own enrollments put the drive on. */
async function accountHostedDriveOrigin(
  currentDriveSubject: string | undefined,
): Promise<string | undefined> {
  const managedAccount = await getManagedAccount().catch(() => null);

  if (!managedAccount) {
    return undefined;
  }

  const enrollments = await getManagedEnrollments().catch(
    () => [] as ManagedEnrollmentSummary[],
  );

  const withOrigin = enrollments.filter(
    // A placement is not a hosted copy. Keep the source until the node
    // reports data, including after an interrupted setup. Only statuses the
    // node serves count: a Suspended (or unknown) enrollment is off the node's
    // allowlist, and pointing the drive at it gets every write refused.
    e =>
      (e.status === /* @wc-ignore */ 'Active' ||
        e.status === /* @wc-ignore */ 'Error') &&
      e.resource_count !== 0 &&
      e.http_origin,
  );

  // Match by the drive currently in view; with no drive in view yet, only
  // resolve when there's exactly one candidate — with several, guessing
  // wrong is worse than waiting for a drive subject to disambiguate.
  const match = currentDriveSubject
    ? withOrigin.find(e => e.drive_subject === currentDriveSubject)
    : withOrigin.length === 1
      ? withOrigin[0]
      : undefined;

  return httpOrigin(match?.http_origin);
}

/**
 * The node hosting `drive`, whoever enrolled it. The control plane answers
 * for the drive alone (`GET /drives/host`), the same rule as above: a served
 * enrollment whose node already holds data. A control plane too old to know
 * the route, or none at all, answers nothing, which keeps today's behaviour.
 */
async function driveHostedOrigin(drive: string): Promise<string | undefined> {
  if (!hasManagedApi()) return undefined;

  try {
    const response = await managedFetch(
      `/drives/host?${new URLSearchParams({ drive })}`,
    );

    if (!response.ok || response.status === 204) return undefined;

    const body = (await response.json()) as { http_origin?: unknown };

    return httpOrigin(
      typeof body.http_origin === 'string' ? body.http_origin : undefined,
    );
  } catch {
    return undefined;
  }
}

function httpOrigin(value: string | null | undefined): string | undefined {
  if (!value) return undefined;

  try {
    const url = new URL(value);

    return ['http:', 'https:'].includes(url.protocol) ? url.origin : undefined;
  } catch {
    return undefined;
  }
}

/** Connect before sign-in checks data, rather than waiting for the app gate. */
export async function connectHostedDrive(
  store: {
    setServerUrl(url: string): void;
    unregisterLocalOnlyDrive(drive: string): void;
    waitForServerConnected(timeoutMs: number): Promise<boolean>;
  },
  drive: string,
  persistServer: (url: string) => void,
  lookupTimeoutMs = 8_000,
): Promise<boolean> {
  // Only race the read: a late lookup must never switch an already restored session.
  const origin = await withDeadline(
    resolveHostedDriveOrigin(drive),
    lookupTimeoutMs,
    undefined,
  );

  if (!origin) return false;

  store.unregisterLocalOnlyDrive(drive);
  store.setServerUrl(origin);
  persistServer(origin);
  // Let the first resource/query use WS; HTTP remains available if WS cannot connect.
  await store.waitForServerConnected(3_000);

  return true;
}

export async function evaluateServerReconciliation(
  currentServerUrl: string,
  currentDriveSubject: string | undefined,
): Promise<ServerReconcileResult> {
  const origin = await resolveHostedDriveOrigin(currentDriveSubject);

  if (!origin) return { ok: true };

  let expectedOrigin: string;
  let actualOrigin: string;

  try {
    expectedOrigin = new URL(origin).origin;
    actualOrigin = new URL(currentServerUrl).origin;
  } catch {
    // A malformed URL on either side isn't this function's problem to fix.
    return { ok: true };
  }

  if (expectedOrigin === actualOrigin) {
    return { ok: true };
  }

  return { ok: false, expectedOrigin };
}

export async function assertAgentMatchesManagedAccount(
  agentSubject: string,
): Promise<void> {
  const result = await evaluateIdentityReconciliation(agentSubject);

  if (result.ok) return;

  throw new Error(
    `This device is signed in to a different Atomic agent than your ${PRODUCT_NAME} account. Resolve the identity mismatch before continuing.`,
  );
}

/**
 * The least a store needs to answer `localAgentIsDisposable`. Narrow so the
 * test can hand in a stub instead of a whole Store.
 */
export type AgentResourceReader = {
  getResource(subject: string): Promise<{
    error?: unknown;
    get(property: string): unknown;
  }>;
};

/**
 * What the device's agent has on it: a workspace (`some`), nothing (`none`,
 * the demo guest or an identity that never got one), or no answer because its
 * resource could not be read (`unknown`). Real accounts get a personal drive
 * during onboarding; guests never do (same test `ensureAgentForDemo` uses).
 *
 * The reconcile gate needs all three: `unknown` must not be mistaken for
 * `none`, or an identity that is merely offline would be switched out with
 * its drives still on it.
 */
export async function localAgentWorkspace(
  store: AgentResourceReader,
  agentSubject: string,
): Promise<'some' | 'none' | 'unknown'> {
  try {
    const resource = await store.getResource(agentSubject);

    if (resource.error) return 'unknown';

    return resource.get(core.properties.personalDrive) ? 'some' : 'none';
  } catch {
    return 'unknown';
  }
}

/**
 * Whether the device's agent is one nobody would miss: the demo guest, or an
 * identity that never got a workspace. A failed read is not disposable: it
 * does not establish that the identity has no workspace.
 */
export async function localAgentIsDisposable(
  store: AgentResourceReader,
  agentSubject: string,
): Promise<boolean> {
  // Native first launch and account recovery can race the local node.
  return (await localAgentWorkspace(store, agentSubject)) === 'none';
}

export function shortDid(subject: string): string {
  if (subject.length <= 28) return subject;

  return `${subject.slice(0, 18)}…${subject.slice(-8)}`;
}
