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
import { getRecoverySecret } from './recovery';
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
  const agents = new Set<string>();

  for (const enrollment of enrollments) {
    if (enrollment.status === 'Disabled') continue;

    if (enrollment.agent_subject) {
      agents.add(enrollment.agent_subject);
    }
  }

  return [...agents];
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
    getRecoverySecret(managedAccount).catch(() => null),
    getManagedEnrollments(false, managedAccount).catch(
      () => [] as ManagedEnrollmentSummary[],
    ),
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

  if (recoveryAgent && recoveryAgent !== localAgentSubject) {
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
    !enrollmentAgents.includes(localAgentSubject)
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

  if (bindingAgent && bindingAgent !== localAgentSubject) {
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
 * Returns whether the Store's current `serverUrl` origin matches the node
 * actually hosting the active drive, per the signed-in account's
 * enrollments. When there is no Managed session, always ok (self-hosted /
 * local-only) — mirrors `evaluateIdentityReconciliation`'s short-circuit.
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
  const managedAccount = await getManagedAccount().catch(() => null);

  if (!managedAccount) {
    return undefined;
  }

  const enrollments = await getManagedEnrollments(false, managedAccount).catch(
    () => [] as ManagedEnrollmentSummary[],
  );

  const withOrigin = enrollments.filter(
    // A placement is not a hosted copy. Keep the source until the node
    // reports data, including after an interrupted setup.
    e =>
      e.status !== 'Disabled' &&
      e.status !== /* @wc-ignore */ 'Pending' &&
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

  if (!match?.http_origin) return undefined;

  try {
    const url = new URL(match.http_origin);

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
 * Whether the device's agent is one nobody would miss: the demo guest, or an
 * identity that never got a workspace. Real accounts get a personal drive
 * during onboarding; guests never do (same test `ensureAgentForDemo` uses).
 *
 * This is what decides whether the reconcile gate may swap the agent out
 * silently. It used to swap every time — and a fresh local identity with a
 * workspace on it was replaced, without a word, the moment its owner signed
 * in to the portal with an email that already had one (staging, 2026-09-03).
 */
export async function localAgentIsDisposable(
  store: AgentResourceReader,
  agentSubject: string,
): Promise<boolean> {
  try {
    const resource = await store.getResource(agentSubject);

    if (resource.error) return true;

    return !resource.get(core.properties.personalDrive);
  } catch {
    return true;
  }
}

export function shortDid(subject: string): string {
  if (subject.length <= 28) return subject;

  return `${subject.slice(0, 18)}…${subject.slice(-8)}`;
}
