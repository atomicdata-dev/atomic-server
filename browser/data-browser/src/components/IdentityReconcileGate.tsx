import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useStore } from '@tomic/react';
import { useLocation, useNavigate } from '@tanstack/react-router';
import { useSettings } from '../helpers/AppSettings';
import {
  clearManagedAccountBinding,
  evaluateIdentityReconciliation,
  evaluateServerReconciliation,
  localAgentIsDisposable,
  logoutManagedSession,
  PRODUCT_NAME,
  syncDeviceDirectory,
  writeManagedAccountBinding,
} from '../helpers/managed';
import { paths } from '../routes/paths';
import { Button } from './Button';
import { Column } from './Row';
import {
  CardSubtitle,
  CardTitle,
  OnboardingCard,
  OnboardingWrap,
  Shell,
} from '../views/getting-started/chrome';

type GateProps = {
  children: React.ReactNode;
};

/** A local identity worth asking about, and the account that wants to replace it. */
type Conflict = {
  managedAccountEmail: string;
};

/**
 * Keeps the device's Atomic agent aligned with the signed-in Managed Sync account
 * — silently wherever silence loses nothing. The agent layer is not surfaced
 * to a user who only thinks in terms of their account (see the control-plane
 * contract doc, decision 2026-06-25); the one exception below is the case
 * where staying silent throws a workspace away.
 *
 * On a Managed Sync session whose account agent differs from the device agent:
 * - **Account has a restorable backup** (`recovery_agent`) and the local agent
 *   is disposable (the demo guest, an identity with no workspace) → send the
 *   user to the welcome/recover flow ("unlock your data"), which replaces the
 *   local agent. Nothing is dropped here; the local agent stays until recovery
 *   lands.
 * - **Same, but the local agent has a workspace** → ask. Someone who made an
 *   identity here and then signed in to the portal with an email that already
 *   has one was, until 2026-09-03, switched to the old identity without a
 *   word. One email has one identity; which one that is stays their call.
 * - **Otherwise** → adopt this device's agent (bind it to the account) so it
 *   becomes the account's agent. No prompt, no logout.
 *
 * With no Managed session (self-hosted / local-only), reconciliation is a no-op
 * and the agent is simply primary.
 */
export function IdentityReconcileGate({
  children,
}: GateProps): React.JSX.Element {
  const store = useStore();
  const { agent, setServer } = useSettings();
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const [checking, setChecking] = useState(true);
  const [conflict, setConflict] = useState<Conflict | null>(null);
  const [resolving, setResolving] = useState(false);
  // Re-checks fire on every `agent?.subject` change (e.g. a device
  // creating/accepting-as a brand new local agent, not just managed-sync
  // sign-in/out). Blanking `children` on every one of those unmounts the
  // whole `<Outlet/>` subtree — including in-flight async flows lower down
  // (the invite accept dialog is one) — which is the opposite of "silent".
  // Only the very first check (initial mount) blanks the screen, matching
  // the doc comment's intent of not flashing the wrong agent; later
  // re-checks resolve in the background without disturbing the mounted UI.
  const hasCheckedOnceRef = useRef(false);

  // The welcome/recover flow does its own convergence; don't double-handle it.
  const skip =
    pathname === paths.welcome || pathname.startsWith(`${paths.welcome}/`);

  const converge = useCallback(async () => {
    if (skip) {
      setChecking(false);
      hasCheckedOnceRef.current = true;

      return;
    }

    if (!hasCheckedOnceRef.current) {
      setChecking(true);
    }

    const localAgent = agent?.subject ?? store.getAgent()?.subject ?? undefined;
    const result = await evaluateIdentityReconciliation(localAgent);

    if (!result.ok && result.issue.reason === 'recovery_agent') {
      const disposable =
        !result.issue.localAgentSubject ||
        (await localAgentIsDisposable(store, result.issue.localAgentSubject));

      if (!disposable) {
        // Two identities that both have something on them. Render the
        // question instead of the app, so nothing is used as the wrong one
        // meanwhile.
        setConflict({ managedAccountEmail: result.issue.managedAccountEmail });

        return;
      }

      // The account has a restorable identity. Unlock it via the recover flow;
      // it replaces the local agent. Keep `checking` true so we render nothing
      // during the redirect rather than flashing the app as the wrong agent.
      navigate({ to: paths.welcome, replace: true });

      return;
    }

    if (!result.ok && result.issue.localAgentSubject) {
      // Adopt this device's agent as the account's agent — no UI.
      writeManagedAccountBinding(
        result.issue.managedAccountEmail,
        result.issue.localAgentSubject,
      );
    }

    // Keep `serverUrl` pointed at the node actually hosting the active
    // drive — silently, like the agent check above. Needed once the app is
    // served from a fixed origin instead of the node's own domain: a fresh
    // device has no stored server yet, and a migrated drive's stored value
    // goes stale. See reconcile.ts for why this can't be derived from the
    // drive's `did:` subject directly.
    const serverResult = await evaluateServerReconciliation(
      store.getServerUrl(),
      store.getDrive(),
    );

    if (!serverResult.ok) {
      setServer(serverResult.expectedOrigin);
    }

    // Announce this device to the account's device directory, seed KnownPeers
    // from it, and auto-connect the account's other devices with the active
    // drive (zero-scan pairing — no manual "Sync now"). Fire-and-forget:
    // routing hints only, must never delay or gate the app.
    void syncDeviceDirectory(store.getDrive(), store.getAgent());

    setConflict(null);
    setChecking(false);
    hasCheckedOnceRef.current = true;
  }, [agent?.subject, skip, store, navigate, setServer]);

  useEffect(() => {
    void converge();
  }, [converge]);

  /** Switch this browser to the account's identity: the recover flow does it. */
  function switchToAccount() {
    setConflict(null);
    navigate({ to: paths.welcome, replace: true });
  }

  /**
   * Keep the identity that is here. The stale thing is then the portal
   * session — end it, as signing in with a secret already does when the two
   * disagree — and converge again, which now finds no account and lets the
   * local agent be primary.
   */
  async function keepLocal() {
    setResolving(true);

    try {
      clearManagedAccountBinding();
      await logoutManagedSession();
    } finally {
      setResolving(false);
      setConflict(null);
      void converge();
    }
  }

  if (skip) {
    return <>{children}</>;
  }

  if (conflict) {
    return (
      <Shell>
        <OnboardingWrap>
          <OnboardingCard data-testid='identity-conflict'>
            <Column gap='1rem'>
              <CardTitle>This email already has an identity</CardTitle>
              <CardSubtitle>
                {conflict.managedAccountEmail} is backed up with an identity
                that is not the one this browser is using. An account has one
                identity — which one should this be?
              </CardSubtitle>
              <Button
                type='button'
                onClick={switchToAccount}
                disabled={resolving}
                data-testid='identity-conflict-switch'
              >
                Switch to my account&apos;s identity
              </Button>
              <CardSubtitle>
                Restores it here. The identity you made in this browser stays
                reachable only with its agent secret.
              </CardSubtitle>
              <Button
                type='button'
                subtle
                onClick={() => void keepLocal()}
                disabled={resolving}
                data-testid='identity-conflict-keep'
              >
                {resolving ? 'Signing out…' : 'Keep this one'}
              </Button>
              <CardSubtitle>
                Signs this browser out of {PRODUCT_NAME}. Nothing here is backed
                up until it has an account of its own.
              </CardSubtitle>
            </Column>
          </OnboardingCard>
        </OnboardingWrap>
      </Shell>
    );
  }

  if (checking && !hasCheckedOnceRef.current) {
    return <></>;
  }

  return <>{children}</>;
}
