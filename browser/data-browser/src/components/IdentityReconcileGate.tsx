import { signInAccountWithAgent } from '../helpers/managed/agentSession';
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useStore, type Store } from '@tomic/react';
import { useLocation, useNavigate } from '@tanstack/react-router';
import * as Sentry from '@sentry/react';
import { useSettings } from '../helpers/AppSettings';
import { archiveStoredAgent } from '../helpers/agentStorage';
import {
  clearManagedAccountBinding,
  evaluateIdentityReconciliation,
  evaluateServerReconciliation,
  linkAgentToAccount,
  localAgentWorkspace,
  logoutManagedSession,
  PRODUCT_NAME,
  sameAgent,
  syncDeviceDirectory,
  writeManagedAccountBinding,
} from '../helpers/managed';
import {
  applyPendingDriveHandover,
  handOverDrives,
} from '../helpers/managed/driveHandover';
import {
  importDriveCarryOver,
  stageDriveCarryOver,
} from '../helpers/managed/driveCarryOver';
import { isClientDbEnabled } from '../helpers/clientDbMode';
import {
  readInteractiveDemo,
  readTemplateDemo,
} from '../chunks/Templates/demoSession';
import { paths } from '../routes/paths';
import { Button } from './Button';
import { Column } from './Row';
import {
  CardError,
  CardSubtitle,
  CardTitle,
  OnboardingCard,
  OnboardingWrap,
  Shell,
} from '../views/getting-started/chrome';

type GateProps = {
  children: React.ReactNode;
};

/** The account whose identity could not take over without losing drives. */
type Conflict = {
  managedAccountEmail: string;
  /** This browser's identity, still active. */
  from: string;
  /** The account's identity. */
  to: string;
  /**
   * Whether its workspace can be brought into the account: only an identity
   * that never hosted anything, like a demo guest. A hosted or synced drive
   * has an enrollment tied to `from` that the account cannot take over from
   * here.
   */
  canBringAlong: boolean;
};

/**
 * Keep `from`'s key on this device before the switch, without handing its
 * drives to anyone. False when that failed, reported like a failed handover.
 */
async function archiveOrReport(from: string): Promise<boolean> {
  try {
    await archiveStoredAgent(from);

    return true;
  } catch (error) {
    Sentry.captureException(
      new Error('keeping the previous identity failed; asking instead', {
        cause: error,
      }),
      { tags: { flow: 'identity-reconcile' } },
    );

    return false;
  }
}

/**
 * Hand `from`'s drives to `to` before the switch (see `driveHandover.ts`).
 * False when that failed, reported: the one case the gate still asks about.
 * Outside the component, where the React Compiler handles try/catch.
 */
async function handOverOrReport(
  store: Store,
  from: string,
  to: string,
): Promise<boolean> {
  try {
    await handOverDrives(store, {
      from,
      to,
      personalDrive: store.getAgent()?.privateDrive,
      skip: [readInteractiveDemo()?.drive, readTemplateDemo()?.drive],
      archiveIdentity: archiveStoredAgent,
      // Without a local database there is no identity database to leave the
      // drives behind in.
      carryOver: isClientDbEnabled()
        ? drives => stageDriveCarryOver(store, { from, to, drives })
        : undefined,
    });

    return true;
  } catch (error) {
    Sentry.captureException(
      new Error(
        'drive handover to the account identity failed; asking instead',
        {
          cause: error,
        },
      ),
      { tags: { flow: 'identity-reconcile' } },
    );

    return false;
  }
}

/**
 * Keeps the device's Atomic agent aligned with the signed-in Managed Sync account
 * — silently. The agent layer is not surfaced to a user who only thinks in
 * terms of their account (see the control-plane contract doc, decision
 * 2026-06-25).
 *
 * On a Managed Sync session whose account agent differs from the device agent:
 * - **Account has a restorable backup** (`recovery_agent`) → the account's
 *   identity wins: send the user to the welcome/recover flow ("unlock your
 *   data"), which replaces the local agent. When the local agent has (or may
 *   have) a workspace, first hand its drives to the account agent, copy
 *   its local-only drives for the account's database, and keep its key on
 *   the device (see `driveHandover.ts`), so the switch loses nothing. Asking which identity to keep (2026-09-03) put a question about
 *   agents in front of people who only know their account.
 * - **Same, but the handover failed** → ask, as a last resort: switching now
 *   could lock a workspace away. For an identity that never hosted anything
 *   the first answer is to bring its workspace along after all (the same
 *   handover, tried again); switching without it and keeping this identity
 *   stay as fallbacks. A hosted or synced identity is only ever kept: its
 *   drives' enrollments are tied to it, and the account cannot re-enroll
 *   them from here.
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
  const [bringing, setBringing] = useState(false);
  const [bringFailed, setBringFailed] = useState(false);
  const [reconcileAttempt, setReconcileAttempt] = useState(0);
  // Re-checks fire on every `agent?.subject` change (e.g. a device
  // creating/accepting-as a brand new local agent, not just managed-sync
  // sign-in/out). Blanking `children` on every one of those unmounts the
  // whole `<Outlet/>` subtree — including in-flight async flows lower down
  // (the invite accept dialog is one) — which is the opposite of "silent".
  // Only the very first check (initial mount) blanks the screen, matching
  // the doc comment's intent of not flashing the wrong agent; later
  // re-checks resolve in the background without disturbing the mounted UI.
  const hasCheckedOnceRef = useRef(false);

  // Identity setup owns its transition. Reconciling a half-created dev agent
  // can classify it as disposable and redirect before its drive is saved.
  // The demo is the same: it makes (or keeps) a guest identity itself, and a
  // signed-in visitor is sent to their own drive from there. Holding it back
  // for this check cost a first visit a cold round trip to the account
  // server before setup could even start. The check runs as soon as the demo
  // navigates on.
  const skip =
    pathname === paths.devDrive ||
    pathname === paths.demo ||
    pathname === paths.welcome ||
    pathname.startsWith(`${paths.welcome}/`);

  const converge = useCallback(
    async (signal: AbortSignal) => {
      if (skip) {
        setChecking(false);
        hasCheckedOnceRef.current = true;

        return;
      }

      if (!hasCheckedOnceRef.current) {
        setChecking(true);
      }

      const localAgent =
        agent?.subject ?? store.getAgent()?.subject ?? undefined;
      // An old response must not undo a deliberate sign-in, lock, or navigation
      // into onboarding. Check after every await, including workspace discovery.
      const isCurrent = () =>
        !signal.aborted &&
        localAgent === (store.getAgent()?.subject ?? undefined);
      // One sign-in: an unlocked identity with no account session signs the
      // account in by itself, and the check runs again once it has. In the
      // background, so the app never waits on the account server for it.
      void signInAccountWithAgent(store.getAgent() ?? undefined).then(
        signedIn => {
          if (signedIn && isCurrent()) setReconcileAttempt(n => n + 1);
        },
      );
      const result = await evaluateIdentityReconciliation(localAgent);
      if (!isCurrent()) return;

      if (!result.ok && result.issue.reason === 'recovery_agent') {
        const { localAgentSubject: from, expectedAgentSubject: to } =
          result.issue;
        // Unknown counts as having a workspace: an agent that is merely
        // offline must not be switched out with its drives still on it.
        const workspace = from
          ? await localAgentWorkspace(store, from)
          : 'none';
        if (!isCurrent()) return;

        if (workspace !== 'none' && from && to) {
          // Only a demo guest's work moves into the account. A guest has no
          // account of its own, so its drives belong to whoever is signing in
          // here. Any other identity may be someone else's on a shared
          // browser: its key is kept on this device and nothing is copied or
          // shared with the account.
          const canBringAlong = store.isLocalOnlyDrive(from);
          const handedOver = canBringAlong
            ? await handOverOrReport(store, from, to)
            : await archiveOrReport(from);
          if (!isCurrent()) return;

          if (!handedOver) {
            // Switching now could lock a workspace away. Render the question
            // instead of the app, so nothing is used as the wrong one meanwhile.
            setConflict({
              managedAccountEmail: result.issue.managedAccountEmail,
              from,
              to,
              canBringAlong,
            });

            return;
          }
        }

        // The account has a restorable identity. Unlock it via the recover flow;
        // it replaces the local agent. Keep `checking` true so we render nothing
        // during the redirect rather than flashing the app as the wrong agent.
        navigate({
          to: paths.welcome,
          search: {
            step: 'signin',
            return_to: pathname === paths.agentSettings ? 'agent' : undefined,
          },
          replace: true,
        });

        return;
      }

      // The switch the handover above prepared has landed: import the
      // local-only drives it carried over and list the drives it handed over
      // in the account's home. Fire-and-forget, like the device
      // directory below; it retries on the next check until it succeeds.
      if (localAgent)
        void applyPendingDriveHandover(store, localAgent, subject =>
          importDriveCarryOver(store, subject),
        );

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
      if (!isCurrent()) return;

      if (!serverResult.ok) {
        setServer(serverResult.expectedOrigin);
      }

      // Announce this device to the account's device directory, seed KnownPeers
      // from it, and auto-connect the account's other devices with the active
      // drive (zero-scan pairing — no manual "Sync now"). Fire-and-forget:
      // routing hints only, must never delay or gate the app.
      void syncDeviceDirectory(store.getDrive(), store.getAgent());
      // Tell the account which identity it now uses, so services that only
      // see a signature (the integration proxy) can tell whose account it is.
      // Fire-and-forget too: it never throws, and tries once per session.
      void linkAgentToAccount(store.getAgent());

      setConflict(null);
      setChecking(false);
      hasCheckedOnceRef.current = true;
    },
    [agent?.subject, skip, store, navigate, setServer, pathname],
  );

  useEffect(() => {
    const controller = new AbortController();
    void converge(controller.signal);

    return () => controller.abort();
  }, [converge, reconcileAttempt]);

  /** Switch this browser to the account's identity: the recover flow does it. */
  function switchToAccount() {
    setConflict(null);
    setBringFailed(false);
    navigate({
      to: paths.welcome,
      search: {
        step: 'signin',
        return_to: pathname === paths.agentSettings ? 'agent' : undefined,
      },
      replace: true,
    });
  }

  /**
   * Bring this browser's workspace into the account, then switch: while this
   * identity can still sign, give the account's identity write on every drive
   * it owns and list them for the account (`driveHandover.ts`). Old commits
   * keep their author; everything stays editable as the account.
   */
  async function bringAlong(current: Conflict) {
    setBringing(true);
    setBringFailed(false);

    try {
      // Still the identity the conflict was about: a grant signed by any
      // other would not be this workspace's owner speaking.
      const active = store.getAgent()?.subject;

      if (
        active &&
        sameAgent(active, current.from) &&
        (await handOverOrReport(store, current.from, current.to))
      ) {
        switchToAccount();

        return;
      }

      setBringFailed(true);
    } finally {
      setBringing(false);
    }
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
      setReconcileAttempt(attempt => attempt + 1);
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
              <CardTitle>Choose an identity for this browser</CardTitle>
              <CardSubtitle>
                This browser has an identity that is different from the one
                saved for {conflict.managedAccountEmail}. Choose which identity
                you want to use here.
              </CardSubtitle>
              {conflict.canBringAlong ? (
                <>
                  <Button
                    type='button'
                    onClick={() => void bringAlong(conflict)}
                    disabled={resolving || bringing}
                    data-testid='identity-conflict-bring'
                  >
                    {bringing
                      ? 'Bringing your workspace…'
                      : 'Bring this workspace into my account'}
                  </Button>
                  <CardSubtitle>
                    Lets {conflict.managedAccountEmail} edit the drives made on
                    this browser, then switches to that identity. Everything
                    stays editable and is backed up with your account.
                  </CardSubtitle>
                  {bringFailed ? (
                    <CardError role='alert'>
                      Your workspace could not be brought into your account. Try
                      again, or choose one of the options below.
                    </CardError>
                  ) : null}
                </>
              ) : null}
              <Button
                type='button'
                subtle={conflict.canBringAlong}
                onClick={switchToAccount}
                disabled={resolving || bringing}
                data-testid='identity-conflict-switch'
              >
                Use the account identity
              </Button>
              <CardSubtitle>
                Loads the identity saved for {conflict.managedAccountEmail}. You
                can still use this browser&apos;s current identity with its
                agent secret.
              </CardSubtitle>
              <Button
                type='button'
                subtle
                onClick={() => void keepLocal()}
                disabled={resolving || bringing}
                data-testid='identity-conflict-keep'
              >
                {resolving ? 'Signing out…' : 'Keep this browser identity'}
              </Button>
              <CardSubtitle>
                Keeps the identity and data already on this browser, and signs
                you out of {PRODUCT_NAME}. This identity won&apos;t be backed up
                to {conflict.managedAccountEmail}.
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
