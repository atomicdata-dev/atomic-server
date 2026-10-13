// [RECOVERY-RECONSTRUCTED] `helpers/managed/session.ts` was never captured in any
// transcript. Reconstructed from its call sites (reconcile.ts / enrollment.ts
// use `getManagedAccount()` and read `.email`) and the control-plane `GET /api/me`
// route. Mirrors the captured `getManagedUser()` in helpers/managedUsage.ts.

import { PRODUCT_NAME } from './product';
import {
  getManagedDeviceToken,
  hasManagedApi,
  managedFetch,
  setManagedDeviceToken,
} from './api';

export type ManagedAccount = {
  /** The account key backups and bindings are stored under (`owner_email`).
   * For older accounts it is their address; newer ones have an `acct_` id. */
  email: string;
  /** The address to show. Absent from control planes before account ids. */
  address?: string;
  /** The person turned assisted recovery off in their settings. */
  assisted_recovery_off?: boolean;
  created_at?: number;
};

/** The address to show for an account. */
export function accountAddress(account: ManagedAccount): string {
  return account.address ?? account.email;
}

let sessionGeneration = 0;
let pendingLogouts = 0;

/**
 * How long a settled answer is served without asking again. A signed-out
 * visitor otherwise re-asked on every hook retry and every backup flush, for
 * as long as the page stayed open.
 */
export const SESSION_CACHE_TTL_MS = 30_000;

let settled:
  | {
      generation: number;
      token: string | null;
      account: ManagedAccount | null;
      at: number;
    }
  | undefined;

function listenerRegistry() {
  const listeners = new Set<() => void>();

  return {
    add(listener: () => void): () => void {
      listeners.add(listener);

      return () => {
        listeners.delete(listener);
      };
    },
    run() {
      for (const listener of listeners) listener();
    },
  };
}

const sessionChangeListeners = listenerRegistry();
const logoutListeners = listenerRegistry();

/** Run when a sign-in lands in this tab (or the session was otherwise replaced). */
export function onManagedSessionChanged(listener: () => void): () => void {
  return sessionChangeListeners.add(listener);
}

/**
 * Something in this tab may have changed who is signed in (a passkey, an
 * email link, a device link, an agent sign-in). Forget the settled answer and
 * any request that started before, so the next read asks again.
 */
export function noteManagedSessionChanged(): void {
  sessionGeneration++;
  settled = undefined;
  inFlight = undefined;
  sessionChangeListeners.run();
}

// Another tab or window can sign in or out through the shared cookie; the
// moment the user returns here is when that is worth finding out.
if (typeof window !== 'undefined') {
  const forget = () => {
    settled = undefined;
  };

  window.addEventListener('focus', forget);
  window.addEventListener('pageshow', forget);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') forget();
  });
}

/**
 * The signed-in Managed Sync account (cookie session against the control plane),
 * or null when not signed in. 204/401 both mean "no session".
 *
 * The last settled answer is reused for `SESSION_CACHE_TTL_MS`. Callers that
 * wait for a sign-in to land pass `fresh` (or call `noteManagedSessionChanged`
 * once it did).
 */
export async function getManagedAccount(
  options: { fresh?: boolean } = {},
): Promise<ManagedAccount | null> {
  if (pendingLogouts > 0 || !hasManagedApi()) return null;

  // Callers asking at the same moment share one request. A page load asks from
  // several places at once (the identity gate, the demo, sync status), and on a
  // first visit each one waited on its own cold cross-origin round trip.
  const generation = sessionGeneration;
  // A device linked in the meantime asks with a different credential.
  const token = getManagedDeviceToken();

  if (
    !options.fresh &&
    settled?.generation === generation &&
    settled.token === token &&
    Date.now() - settled.at < SESSION_CACHE_TTL_MS
  ) {
    return settled.account;
  }

  if (inFlight?.generation === generation && inFlight.token === token) {
    return inFlight.promise;
  }

  const promise = fetchManagedAccount(generation)
    .then(account => {
      if (generation === sessionGeneration) {
        settled = { generation, token, account, at: Date.now() };
      }

      return account;
    })
    .finally(() => {
      if (inFlight?.promise === promise) inFlight = undefined;
    });
  inFlight = { generation, token, promise };

  return promise;
}

/** Whether this client can authenticate to the control plane at all. */
export async function hasManagedSession(): Promise<boolean> {
  return !!getManagedDeviceToken() || !!(await getManagedAccount());
}

let inFlight:
  | {
      generation: number;
      token: string | null;
      promise: Promise<ManagedAccount | null>;
    }
  | undefined;

async function fetchManagedAccount(
  generation: number,
): Promise<ManagedAccount | null> {
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

/** Stop account-scoped work before invalidating its credentials. */
export function onManagedLogout(listener: () => void): () => void {
  return logoutListeners.add(listener);
}

/**
 * End the control-plane session too, so signing out on this device is a full
 * sign-out (not just the local Atomic agent). Best-effort: self-hosted / FOSS
 * nodes have no control plane, and an already-signed-out session is a no-op.
 */
export async function logoutManagedSession(): Promise<void> {
  sessionGeneration++;
  settled = undefined;
  pendingLogouts++;
  logoutListeners.run();

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
