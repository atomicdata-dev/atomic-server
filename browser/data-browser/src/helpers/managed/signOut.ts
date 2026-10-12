import { saveAgentToIDB } from '../agentStorage';
import { getManagedApiBase, hasManagedApi } from './api';
import { forgetCachedRecoverySecret } from './recovery';
import { logoutManagedSession } from './session';

/**
 * Sign out of the account and this device together: one sign-in, so one
 * sign-out. The account session ends first, so a sign-in that follows cannot
 * have its new cookie cleared by a late logout response; then the identity's
 * key leaves this device. `forget` also drops the device's copy of the
 * encrypted backup, for a shared or borrowed machine.
 *
 * The caller updates what is on screen (agent, drive, route).
 */
export async function signOutEverywhere({
  agentSubject,
  forget = false,
}: { agentSubject?: string; forget?: boolean } = {}): Promise<void> {
  if (forget) forgetCachedRecoverySecret(agentSubject);
  await logoutManagedSession();
  await saveAgentToIDB(undefined);
}

/**
 * Where the account portal may send someone back to after it signed them out
 * through the app: its own origin only, so this route never becomes an open
 * redirect. Undefined for anything else.
 */
export function portalReturnUrl(
  target: string | undefined,
): string | undefined {
  if (!target || !hasManagedApi()) return undefined;

  try {
    const portal = new URL(getManagedApiBase()).origin;
    const url = new URL(target);

    return url.origin === portal ? url.toString() : undefined;
  } catch {
    return undefined;
  }
}

/** Whether this page was opened from the account portal. */
export function cameFromPortal(referrer = document.referrer): boolean {
  if (!referrer || !hasManagedApi()) return false;

  try {
    return new URL(referrer).origin === new URL(getManagedApiBase()).origin;
  } catch {
    return false;
  }
}
