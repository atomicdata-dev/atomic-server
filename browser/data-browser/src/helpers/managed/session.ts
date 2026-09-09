// [RECOVERY-RECONSTRUCTED] `helpers/managed/session.ts` was never captured in any
// transcript. Reconstructed from its call sites (reconcile.ts / enrollment.ts
// use `getManagedAccount()` and read `.email`) and the control-plane `GET /api/me`
// route. Mirrors the captured `getManagedUser()` in helpers/managedUsage.ts.

import { PRODUCT_NAME } from './product';
import { hasManagedApi, managedFetch, setManagedDeviceToken } from './api';

export type ManagedAccount = {
  email: string;
  created_at?: number;
};

let sessionGeneration = 0;
let pendingLogouts = 0;

/**
 * The signed-in Managed Sync account (cookie session against the control plane),
 * or null when not signed in. 204/401 both mean "no session".
 */
export async function getManagedAccount(): Promise<ManagedAccount | null> {
  if (pendingLogouts > 0) return null;
  const generation = sessionGeneration;
  const response = await managedFetch(`/me`, {});
  if (generation !== sessionGeneration) return null;

  if (response.status === 204 || response.status === 401) {
    return null;
  }

  if (!response.ok) {
    throw new Error(`Could not check ${PRODUCT_NAME} session.`);
  }

  const account = (await response.json()) as ManagedAccount;

  return generation === sessionGeneration ? account : null;
}

const logoutListeners = new Set<() => void>();

/** Stop account-scoped work before invalidating its credentials. */
export function onManagedLogout(listener: () => void): () => void {
  logoutListeners.add(listener);

  return () => {
    logoutListeners.delete(listener);
  };
}

/**
 * End the control-plane session too, so signing out on this device is a full
 * sign-out (not just the local Atomic agent). Best-effort: self-hosted / FOSS
 * nodes have no control plane, and an already-signed-out session is a no-op.
 */
export async function logoutManagedSession(): Promise<void> {
  sessionGeneration++;
  pendingLogouts++;
  for (const listener of logoutListeners) listener();

  try {
    // A FOSS node has no control plane; its own origin answers 405.
    if (!hasManagedApi()) return;
    await managedFetch(`/logout`, {
      method: 'POST',
    });
  } catch {
    // No control plane reachable (self-hosted) — nothing to sign out of.
  } finally {
    // On a linked device the session *is* the token. Signing out ends it,
    // and with it the record of which portal it belonged to.
    setManagedDeviceToken(null);
    pendingLogouts--;
  }
}
