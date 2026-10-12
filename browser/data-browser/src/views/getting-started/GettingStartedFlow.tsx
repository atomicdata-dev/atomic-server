import { Spinner } from '../../components/Spinner';
import { resumeInviteUrl } from '../../helpers/inviteSignup';
import { signInAccountWithAgent } from '../../helpers/managed/agentSession';
import {
  pendingTemplateUrl,
  readPendingTemplate,
} from '../../chunks/Templates/pendingTemplate';
import { WorkspaceLoading } from './WorkspaceLoading';
import {
  PRODUCT_NAME,
  clearManagedAccountBinding,
  logoutManagedSession,
} from '../../helpers/managed';
import toast from 'react-hot-toast';
import React, { FormEvent, useEffect, useRef, useState } from 'react';
import { styled, keyframes } from 'styled-components';
import { useStore } from '@tomic/react';
import { Agent, decodeSecret } from '@tomic/lib';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';
import { useWelcomeLayoutEffect } from '../../hooks/useWelcomeLayoutEffect';
import { useSettings } from '../../helpers/AppSettings';
import { saveAgentToIDB } from '../../helpers/agentStorage';
import { beat } from '../../helpers/deviceLock';
import { fetchPrivateDriveSubject } from '../../helpers/privateDrive';
import { connectHostedDrive, shortDid } from '../../helpers/managed/reconcile';
import { deviceHasDriveData } from '../../helpers/driveData';
import { discoverHomeServerForApp } from '../../helpers/discoverHomeServer';
import { openPrivateHome } from '../../helpers/openPrivateHome';
import { privateHomeNudge } from '../../helpers/privateHomeNudge';
import { withDeadline } from '../../helpers/withDeadline';
import { constructOpenURL } from '../../helpers/navigation';
import { paths } from '../../routes/paths';
import { Button } from '../../components/Button';
import { Column } from '../../components/Row';
import { NewIdentitySection } from '../../components/NewIdentitySection';
import {
  accountAddress,
  getManagedAccount,
} from '../../helpers/managed/session';
import { getManagedPortalUrl } from '../../helpers/managed/cloudSync';
import { safePortalUrl } from '../../helpers/managed/api';
import {
  fetchManagedInfo,
  accountCreationTarget,
  type AccountCreationTarget,
  isHostedDistribution,
} from '../../helpers/managedServer';
import {
  ensureVaultBackup,
  restoreFromVault,
} from '../../helpers/managed/vaultAutoBackup';
import { isOriginWithoutNode } from '../../helpers/originNode';
import { isRunningInTauri } from '../../helpers/tauri';
import { openExternal } from '../../helpers/openExternal';
import {
  buildEnvelopeV2,
  buildEnvelopeWithAssisted,
  buildEnvelopeWithPasskeyAndCode,
  decryptEnvelopeWithAssisted,
  FreshSignInRequiredError,
  hasAssistedWrapper,
  saveRecoverySecret,
  getRecoverySecret,
  getUnlockableRecoverySecret,
  forgetCachedRecoverySecret,
  readUnlockableCachedBackups,
  decryptRecoverySecret,
  decryptEnvelopeV2,
  decryptEnvelopeWithPasskey,
  envelopeWrapperKinds,
  secretAccountConflict,
  upgradeToEnvelopeV2,
  type RecoverySecret,
  type SecretAccountConflict,
} from '../../helpers/managed/recovery';
import { IconButton } from '../../components/IconButton/IconButton';
import { CodeBlock } from '../../components/CodeBlock';
import {
  AccountSignInPanel,
  AccountSignInViaBrowser,
} from './AccountSignInPanel';
import { InputStyled, InputWrapper } from '../../components/forms/InputStyles';
import { FaArrowLeft, FaKey, FaXmark } from 'react-icons/fa6';
import { Logo } from '../../components/Logo';
import { ConnectDeviceStep } from './ConnectDeviceStep';
import {
  canHoldProviderCookie,
  getRememberedProvider,
} from '../../helpers/managed/deviceLink';
import {
  Shell,
  CardTitle,
  CardSubtitle,
  CardError,
  CtaButton,
  OnboardingWrap,
  OnboardingCard,
  FooterBar,
  BackLabel,
} from './chrome';

type Step =
  | 'welcome'
  | 'signin'
  | 'create'
  | 'restore'
  | 'restore-upgraded'
  | 'secret-conflict'
  | 'connect-device'
  | 'opening-workspace';

type RestoreState =
  | { phase: 'checking' }
  | { phase: 'no-session' }
  | { phase: 'no-backup'; email: string }
  | { phase: 'ready'; secret: RecoverySecret; email: string };

type Props = {
  subject: string;
  initialStep?: Step;
};

/**
 * How long sign-in will wait on a server before deciding this device cannot
 * find out where the account's data lives.
 *
 * Generous, because answering slowly is normal on a cold connection and the
 * cost of giving up early is a screen the user did not need. Bounded, because
 * the alternative is what shipped: an await that never settled, and a spinner
 * that never stopped, on a device holding nothing.
 */
const SIGN_IN_LOOKUP_TIMEOUT_MS = 8_000;

/**
 * How long sign-in waits for a vault restore before falling through to the
 * connect-device step. Longer than a lookup, because it downloads the drive;
 * bounded, because the step it falls through to offers the same restore by
 * hand, with a progress bar, which is the better place to wait a long time.
 */
const VAULT_RESTORE_TIMEOUT_MS = 45_000;

const swapIn = keyframes`
  from {
    opacity: 0;
    transform: translateY(10px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
`;

export function GettingStartedFlow({
  initialStep = 'welcome',
}: Props): React.JSX.Element {
  useWelcomeLayoutEffect();
  const store = useStore();
  const navigate = useNavigateWithTransition();
  const { setAgent, setDrive, setServer, setBaseURL, baseURL } = useSettings();
  // When the connected node is "managed" (reports a dashboard/portal URL via
  // /node-info), account creation goes through the portal (email
  // verification). Self-hosted / FOSS nodes report nothing here, so we keep the
  // local DID-agent creation unchanged.
  const [createTarget, setCreateTarget] =
    useState<AccountCreationTarget | null>(null);
  /**
   * Any control plane this build knows of, which is a weaker question than
   * `createTarget` answers.
   *
   * Creating an account locally is a perfectly good outcome, so that decision
   * stays strict: only a node that says it is managed sends people to a portal.
   * Restoring one is different — the portal is the *only* route, so a screen
   * that cannot name one has nothing to offer at all. Resolved through
   * `getManagedPortalUrl`, so a build-time override counts even before any
   * server has answered, which is the state a wiped browser is in. Null on a
   * self-hosted install, where the button stays hidden rather than dead.
   */
  const [knownPortalUrl, setKnownPortalUrl] = useState<string | null>(
    () =>
      safePortalUrl(getManagedPortalUrl() ?? getRememberedProvider()) ?? null,
  );

  useEffect(() => {
    let cancelled = false;
    void fetchManagedInfo(baseURL).then(info => {
      if (cancelled) return;

      setCreateTarget(accountCreationTarget(info));
      // The remembered provider covers the desktop and Android apps: their
      // embedded node names no portal, and the build may not either, but a
      // device that linked once knows exactly where its account lives.
      setKnownPortalUrl(
        safePortalUrl(getManagedPortalUrl(info) ?? getRememberedProvider()) ??
          null,
      );
    });

    return () => {
      cancelled = true;
    };
  }, [baseURL]);
  // A user who just verified their email via the managed portal lands at
  // /app/welcome?from_portal=true. Skip the generic Create/Sign-in choice and go
  // straight into identity creation, with the username prefilled from their
  // account email and the new drive given encrypted backup after create. Sync is
  // the premium option and is not enabled here; see `enableEncryptedBackup`.
  const fromManaged =
    new URLSearchParams(window.location.search).get('from_portal') === 'true';
  // The portal hands the account email in the URL (`?from_portal=true&email=…`)
  // so we can prefill the profile name without an authenticated cross-origin
  // call back to the control plane (whose session cookie we don't have here).
  const emailParam =
    new URLSearchParams(window.location.search).get('email') || undefined;
  // Someone who signed up on the portal with a secret they made there: that
  // identity, handed over in the fragment (which no server sees), is the one
  // to open, not a new one. Read once and taken out of the address bar.
  const [presetKeys] = useState(() =>
    fromManaged ? takeSecretFragment() : undefined,
  );
  // A sign-in guard (clicking a drive you're not signed in for) sends the user
  // here with `next` carrying that drive's subject, so we open straight to the
  // sign-in step and return them to that drive afterwards (not their home).
  const inviteToken = new URLSearchParams(window.location.search).get('invite');
  // A demo guest who chose a template was sent to make an account first; once
  // it exists they go back to that template instead of to their home.
  const [pendingTemplate] = useState(() =>
    fromManaged && !inviteToken ? readPendingTemplate() : undefined,
  );
  const nextDrive =
    new URLSearchParams(window.location.search).get('next') ||
    new URLSearchParams(window.location.search).get('drive') ||
    new URLSearchParams(window.location.search).get('subject') ||
    undefined;
  // Only this named, internal destination is accepted; never navigate to an
  // arbitrary return URL supplied by a link. Adding a passkey needs the local
  // identity unlocked before the account settings can edit its backup.
  const returnToAgent =
    !fromManaged &&
    !inviteToken &&
    !nextDrive &&
    new URLSearchParams(window.location.search).get('return_to') === 'agent';
  const signInRequested =
    new URLSearchParams(window.location.search).get('step') === 'signin';
  const [step, setStep] = useState<Step>(
    fromManaged
      ? 'create'
      : inviteToken
        ? 'restore'
        : nextDrive ||
            returnToAgent ||
            signInRequested ||
            // Hosted builds have no Create/Sign-in/Demo choice: creating an
            // account happens in the portal, so signed-out people get the
            // sign-in options directly.
            (isHostedDistribution() && initialStep === 'welcome')
          ? 'signin'
          : initialStep,
  );
  // Welcome is also the destination for lock, sign-out, recovery and resource
  // guards. A portal configuration is not a reason to leave an unlock flow.
  // Account creation and the explicit Back action can still open the portal.
  const [loading, setLoading] = useState(false);
  const [workspaceStage, setWorkspaceStage] = useState<
    'identity' | 'local' | 'backup'
  >('identity');
  const [error, setError] = useState<Error | undefined>();
  // The drive a freshly signed-in device is missing, handed to the
  // connect-device step. Undefined when no drive resolved at all.
  const [missingDrive, setMissingDrive] = useState<string | undefined>();
  /** Why the vault had nothing for `missingDrive`, if sign-in asked it. */
  const [missingDriveVaultReason, setMissingDriveVaultReason] = useState<
    string | undefined
  >();
  const stepDotsSlotRef = useRef<HTMLDivElement | null>(null);
  const [secretValue, setSecretValue] = useState('');
  /** A pasted secret for another agent, held until the user says which wins. */
  const [secretConflict, setSecretConflict] = useState<
    (SecretAccountConflict & { secret: string }) | null
  >(null);
  /** Shown only after blur/Enter — every prefix of a valid secret is invalid,
   * so erroring while typing would be constant noise. */
  const [secretError, setSecretError] = useState<string | undefined>();
  const [managedUsername, setManagedUsername] = useState<string | undefined>(
    emailParam ? emailParam.split('@')[0] : undefined,
  );
  // Ready immediately for non-managed flows, or when the portal already handed
  // us the email in the URL (no fetch needed).
  const [managedReady, setManagedReady] = useState(
    !fromManaged || !!emailParam,
  );

  // Fallback for older portals that redirect without the `email` param: fetch
  // the managed account email and derive a default username before showing the
  // profile step, so the field comes prefilled. (Requires a managed session in
  // this origin; when absent, we just continue without a prefill.)
  useEffect(() => {
    if (!fromManaged || emailParam) return;
    let cancelled = false;

    void (async () => {
      try {
        const account = await getManagedAccount();

        if (!cancelled && account?.email) {
          setManagedUsername(accountAddress(account).split('@')[0]);
        }
      } catch {
        // Not signed in to the managed (or unreachable) — continue without a
        // prefill; the user can still type a name.
      } finally {
        if (!cancelled) setManagedReady(true);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [fromManaged, emailParam]);

  // The new drive's subject, captured during onAfterCreate so the recovery
  // backup step can reference it.
  const newDriveSubject = useRef<string | undefined>(undefined);

  /**
   * Set the freshly-created drive up with encrypted backup.
   *
   * **Only runs for accounts arriving from the portal** — the call site is
   * `onAfterCreate={fromManaged ? … : undefined}`, so a self-hosted or FOSS
   * install never reaches it and its onboarding is untouched. Nothing about
   * this is baked into the drive: a vault-enrolled drive is an ordinary
   * local-first drive whose owner happens to have a backup.
   *
   * This used to enroll the drive in managed sync instead. Sync is the premium
   * option, so onboarding no longer pushes it: a new account gets blind
   * encrypted backup, and an always-on peer is something they choose from the
   * Sync page. That also puts the honest version of the pitch first — the tier
   * we cannot read comes as standard, and the tier we can read is opt-in.
   *
   * Best-effort, exactly as the sync enrollment was: the identity and drive
   * both exist by the time this runs, so a failure here leaves a working
   * workspace with backup switched off rather than blocking onboarding. The
   * Sync page will offer it again.
   */
  async function enableEncryptedBackup(driveSubject: string) {
    newDriveSubject.current = driveSubject;
    // Enrols and backs up straight away. A brand-new drive is a few KB, and an
    // enrollment with nothing in it would report a protection the account
    // does not yet have. Failures are swallowed inside — see above.
    await ensureVaultBackup(store, driveSubject);
  }

  function requireAgentSubject(): string {
    const agentSubject = store.getAgent()?.subject;

    if (!agentSubject) {
      throw new Error('No agent to back up. Try again.');
    }

    return agentSubject;
  }

  /** Label the passkey carries in the user's password manager. */
  function passkeyUserName(): string {
    return emailParam ?? managedUsername ?? 'Atomic account';
  }

  // The default backup: a random DEK encrypts the agent secret, wrapped both
  // by a newly registered passkey's PRF output and by a generated recovery
  // code. The passkey is the everyday key; the code is for every device the
  // passkey does not reach. A passkey "syncs" only within one vendor's
  // keychain (one made in Firefox on a Mac is not in Google Password Manager
  // on an Android phone), so a passkey-only backup locked people out of their
  // own account on their second device. Returns the plaintext code for
  // NewIdentitySection to show once — it's never sent anywhere.
  async function backupWithPasskey(secret: string): Promise<string> {
    const { request, recoveryCode } = await buildEnvelopeWithPasskeyAndCode({
      secret,
      agentSubject: requireAgentSubject(),
      driveSubject: newDriveSubject.current ?? null,
      userName: passkeyUserName(),
    });
    await saveRecoverySecret(request);

    return recoveryCode;
  }

  // The fallback: the DEK is wrapped by a generated recovery code (Argon2id)
  // instead. Returns the plaintext code for NewIdentitySection to show once —
  // it's never sent anywhere.
  async function backupWithCode(secret: string): Promise<string> {
    const { recoveryCode, request } = await buildEnvelopeV2({
      secret,
      agentSubject: requireAgentSubject(),
      driveSubject: newDriveSubject.current ?? null,
    });
    await saveRecoverySecret(request);

    return recoveryCode;
  }

  // The backup when the account service offers assisted recovery: wrapped by
  // the account alone, so there is no passkey to register and no code to
  // save, and signing in on any other device opens it. Resolves false when
  // the service does not offer it, so the passkey and code step runs as
  // before.
  async function backupWithAccount(secret: string): Promise<boolean> {
    try {
      const request = await buildEnvelopeWithAssisted({
        secret,
        agentSubject: requireAgentSubject(),
        driveSubject: newDriveSubject.current ?? null,
      });
      await saveRecoverySecret(request);

      return true;
    } catch {
      return false;
    }
  }

  // ─── Restore ("Forgot your secret?") ─────────────────────────────────────
  const [restore, setRestore] = useState<RestoreState>({ phase: 'checking' });
  const returnToPortal =
    !!knownPortalUrl &&
    (fromManaged ||
      createTarget?.kind === 'portal' ||
      restore.phase === 'ready' ||
      restore.phase === 'no-backup');
  const [restoreCodeInput, setRestoreCodeInput] = useState('');
  // Set when a v1 (password-only) backup is lazily upgraded to envelope v2
  // during a restore — the user must save this new code before continuing,
  // same reveal-once treatment as onboarding's recovery-backup step.
  const [upgradedCode, setUpgradedCode] = useState<string | null>(null);
  const [secretAfterUpgrade, setSecretAfterUpgrade] = useState<string | null>(
    null,
  );
  const [upgradedCodeSaved, setUpgradedCodeSaved] = useState(false);
  /** Accounts this device holds an unlockable backup for. Several means the
   * sign-in step has to ask which one before raising a passkey prompt. */
  const [knownAccounts, setKnownAccounts] = useState<RecoverySecret[]>([]);

  useEffect(() => {
    if (step !== 'signin' && step !== 'welcome') return;

    setKnownAccounts(readUnlockableCachedBackups());
  }, [step]);
  // Set when the user explicitly picks code entry over the passkey prompt
  // (e.g. they're on a device their passkeys don't sync to).
  const [preferCodeEntry, setPreferCodeEntry] = useState(false);

  // Which unlock affordances this particular backup supports. A v1 blob has
  // neither wrapper kind, so it falls through to the password input.
  const restoreUnlock =
    restore.phase === 'ready'
      ? (() => {
          const kinds = envelopeWrapperKinds(restore.secret);

          return {
            ...kinds,
            showPasskey: kinds.hasPasskey && !preferCodeEntry,
          };
        })()
      : { hasPasskey: false, hasCode: false, showPasskey: false };

  // Check for a managed session + stored backup on both the restore step and
  // the sign-in step: a returning user with a passkey should be offered it
  // straight away, not asked to paste an agent secret with recovery hidden
  // behind "Forgot your secret?".
  /**
   * Bumped when this device gains a provider session mid-step (a device link
   * approved elsewhere), so the check below runs again without leaving the
   * step. A page reload would do the same and lose the user's place.
   */
  const [restoreAttempt, setRestoreAttempt] = useState(0);
  /**
   * Opening the backup with the account alone (assisted recovery), which
   * runs by itself as soon as a signed-in account's backup allows it.
   * `needs-sign-in`: the sign-in is too old to unlock with, so the step
   * offers signing in again next to the passkey and the code.
   */
  const [assistedUnlock, setAssistedUnlock] = useState<
    'idle' | 'trying' | 'needs-sign-in'
  >('idle');

  /**
   * The account's own ways in, above the passkey, code and secret: while the
   * account is unlocking the identity by itself, say so; where there is no
   * session, or it is too old to unlock with, offer the same sign-in options
   * as the portal (the shared `AccountSignIn`), which end back here signed in.
   */
  function accountSignIn() {
    if (restore.phase === 'ready' && assistedUnlock === 'trying') {
      return (
        <CardSubtitle key='account'>Unlocking {restore.email}…</CardSubtitle>
      );
    }

    const offerSignIn =
      !!knownPortalUrl &&
      (restore.phase === 'no-session' ||
        (restore.phase === 'ready' && assistedUnlock === 'needs-sign-in'));

    if (!offerSignIn || !knownPortalUrl) return null;

    const onSignedIn = () => setRestoreAttempt(n => n + 1);

    return (
      <Column key='account' gap='0.75rem'>
        {assistedUnlock === 'needs-sign-in' ? (
          <CardSubtitle>
            Sign in again to open your account on this device.
          </CardSubtitle>
        ) : null}
        {/* The same options either way; an app that cannot hold the
            account cookie finishes each one in the system browser. */}
        {canHoldProviderCookie(knownPortalUrl) ? (
          <AccountSignInPanel
            portalUrl={knownPortalUrl}
            disabled={loading}
            onSignedIn={onSignedIn}
          />
        ) : (
          <AccountSignInViaBrowser
            portalUrl={knownPortalUrl}
            disabled={loading}
            onSignedIn={onSignedIn}
          />
        )}
      </Column>
    );
  }

  /**
   * The account signed in here, when its agent is not the one `agentSubject`
   * names. A pasted secret may simply be another identity the person owns (an
   * older agent, or a local node's), and using it means ending this account's
   * session, which signs them out of the portal too. That is never done
   * without asking (IDENTITY_RECONCILE_SCENARIOS.md scenario 4).
   */
  async function findSecretConflict(
    agentSubject: string,
  ): Promise<SecretAccountConflict | null> {
    try {
      return secretAccountConflict(await getRecoverySecret(), agentSubject);
    } catch {
      // No session, or the control plane is unreachable: nothing to replace.
      return null;
    }
  }

  /**
   * The user chose the pasted secret over the signed-in account. The reconcile
   * gate would otherwise bounce them straight back here, so the account
   * session is the stale thing now: end it, and say which account that was.
   */
  async function releaseConflictingPortalSession(
    conflict: SecretAccountConflict,
  ) {
    try {
      clearManagedAccountBinding();
      await logoutManagedSession();
      toast(`Signed out of ${conflict.email}.`);
    } catch {
      // Already gone, or the control plane is unreachable: nothing to release.
    }
  }

  async function handleSignInWithSecret(
    secret: string,
    confirmed?: SecretAccountConflict,
  ) {
    setLoading(true);
    setError(undefined);

    try {
      const newAgent = await Agent.fromSecret(secret);

      const conflict =
        confirmed ??
        (newAgent.subject
          ? await withDeadline(
              findSecretConflict(newAgent.subject),
              SIGN_IN_LOOKUP_TIMEOUT_MS,
              null,
            )
          : null);

      if (conflict && !confirmed) {
        setSecretConflict({ ...conflict, secret });
        setStep('secret-conflict');

        return;
      }

      setSecretConflict(null);
      setWorkspaceStage('identity');
      setStep('opening-workspace');
      setAgent(newAgent);
      await saveAgentToIDB(secret);
      // However they got in — passkey, code, or secret — the device is open
      // again, so start the clock fresh (see deviceLock.ts).
      beat();

      if (conflict) {
        await withDeadline(
          releaseConflictingPortalSession(conflict),
          SIGN_IN_LOOKUP_TIMEOUT_MS,
          undefined,
        );
      }

      // One sign-in: the identity just unlocked signs the account in too, so
      // the portal is not left asking again. In the background; the app does
      // not need the account session to open.
      void signInAccountWithAgent(newAgent, { proven: true });

      if (inviteToken) {
        navigate(resumeInviteUrl(inviteToken));

        return;
      }

      // Where this sign-in wants to end up: the drive it came from, or the
      // account's own. One target, so there is one gate below — an early
      // return for the guard case is an early return around the gate.
      //
      // Bounded, because both lookups below ask a server and neither fetch has
      // a timeout of its own. On a device that just restored a secret there may
      // be no server that knows this account — the desktop and Android apps
      // embed their own node, which answers, but not about an account it has
      // never seen. That await never settled, so sign-in sat on "Restoring…"
      // forever on exactly the device that had nothing. Not finding out is
      // already a handled outcome here (both helpers have a "no" answer), and
      // it lands on the connect-device step, which is the screen for a device
      // holding none of your data — including its offer to restore from the
      // vault.
      setWorkspaceStage('local');
      const target =
        nextDrive ??
        (await withDeadline(
          fetchPrivateDriveSubject(store, newAgent),
          SIGN_IN_LOOKUP_TIMEOUT_MS,
          undefined,
        ));

      // Resolve hosting before a failed read sends this device to Cloud Vault.
      const hostedByAccount = target
        ? await connectHostedDrive(store, target, setServer)
        : false;

      // No account to ask (or it does not know this drive): the secret alone
      // names the drive, and pkarr says which servers announced it. Only
      // when the server in use does not already have it.
      const hosted =
        hostedByAccount ||
        (!!target &&
          (await discoverHomeServerForApp(store, target, setBaseURL, subject =>
            deviceHasDriveData(store, subject),
          )));

      // Check for existing data before creating anything, so a newly writable
      // home is never mistaken for successful recovery of previous content.
      const canRead = (subject: string, refresh = hosted) =>
        withDeadline(
          deviceHasDriveData(store, subject, { refresh }),
          SIGN_IN_LOOKUP_TIMEOUT_MS,
          false,
        );

      // The home a pre-derivation secret was made for. Its data has not moved
      // to the derived home yet — that is what materializing below does, by
      // adopting its drive lists — so the derived subject alone reports "no
      // data" for an account whose workspace is sitting on the very server
      // they just authenticated against. Answering "your data is on another
      // device" there would be false, and it would skip the adoption that
      // makes it true. Costs nothing for accounts that never had one: a
      // secret minted after derivation carries no `initialDrive`.
      const legacyHome = newAgent.initialDrive;

      let hasData =
        !!target &&
        ((await canRead(target)) ||
          (!!legacyHome &&
            legacyHome !== target &&
            (await canRead(legacyHome))));

      // A device holding nothing may still be one download from holding
      // everything: every account on a managed origin gets an encrypted backup
      // of its drive, so ask the vault before telling the user their data is
      // on another device. Signing in as the account is what unlocks it — the
      // key envelope opens with the agent's signature — so this is the first
      // moment it can happen. Anything short of a restore (no session, no
      // backup, an empty one, a failure) falls through to the connect-device
      // step, which still offers the same restore by hand.
      // Why the vault had nothing, for the connect-device step to show. Five
      // different situations answer `no-backup`; a screen that says only
      // "your data is on another device" hides which one this is.
      let vaultReason: string | undefined;

      if (!hasData && target && !returnToAgent) {
        setWorkspaceStage('backup');
        const restored = await withDeadline(
          restoreFromVault(store, target),
          VAULT_RESTORE_TIMEOUT_MS,
          { status: 'no-backup' as const, reason: 'timed out' },
        );

        if (restored.status === 'restored') {
          hasData = await canRead(target, false);
        } else if (restored.status === 'no-backup') {
          vaultReason = restored.reason;
        } else {
          vaultReason = restored.error.message;
        }
      }

      // On an origin with no node the account's drive lives only here — a
      // restored one exactly like one made here, and one whose data has not
      // arrived yet just as much: it is still the place this identity writes
      // to. Without this every commit would park in the outbox waiting for a
      // server that is not coming. The agent's own subject is deliberately
      // not registered: `fetchPrivateDriveSubject` answers a local-only agent
      // with its secret's `initialDrive`, which for an account made elsewhere
      // is that server's URL, and handing that to `setDrive` moves the app.
      if (target && isOriginWithoutNode(store.getServerUrl())) {
        store.registerLocalOnlyDrive(target);
      }

      setDrive(target ?? '');

      // Recover first, but connecting a device is optional for the identity's
      // own home. A foreign requested workspace must never be synthesized.
      const home =
        !hasData && target && !returnToAgent
          ? await openPrivateHome(store, target, true)
          : undefined;

      if (home) {
        if (home === 'created') privateHomeNudge();
        navigate(constructOpenURL(target!));
      } else if (hasData) {
        // The home drive is derived from the key rather than looked up, so
        // nothing else will ever write it — `fetchPrivateDriveSubject` above
        // computes the subject but does not materialize it. Signing in is the
        // one deliberate moment to do it; leaving it to whichever render-time
        // resolver asked first is what let a bad derivation mint hundreds of
        // drives instead of one.
        //
        // Here it usually finds the drive the gate just read and returns it
        // untouched — but that path still seeds the switcher list and adopts
        // drives from an older, pre-derivation home, which is why it runs on
        // the "we have it" branch rather than only on the "we don't" one. It
        // must not run before the gate: a drive written a moment ago is not
        // evidence that this device has the account's data.
        await withDeadline(
          store.ensurePrivateDrive().then(() => undefined),
          SIGN_IN_LOOKUP_TIMEOUT_MS,
          undefined,
        );

        // Every account gets a backup, not only the ones onboarding made
        // here: this is the one moment an existing account is known to be on
        // a device that holds its data. Not awaited — the first pass seals
        // the whole drive, and sign-in should not wait on an upload.
        void ensureVaultBackup(store, target!);

        navigate(
          returnToAgent ? paths.agentSettings : constructOpenURL(target!),
        );
      } else if (returnToAgent) {
        // Passkey management needs the key, not a downloaded copy of the drive.
        navigate(paths.agentSettings);
      } else {
        setMissingDrive(target);
        setMissingDriveVaultReason(vaultReason);
        setStep('connect-device');
      }
    } catch (err) {
      setError(
        err instanceof Error ? err : new Error('Could not parse that secret.'),
      );
      setStep('signin');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (step !== 'restore' && step !== 'signin') return;
    let cancelled = false;
    setRestore({ phase: 'checking' });
    setError(undefined);

    void (async () => {
      try {
        // The backup is checked *before* the session, deliberately: this
        // device may hold a cached copy of the ciphertext, in which case a
        // passkey alone gets the user back in — no email, no network. Only
        // when there's nothing to unlock does the portal session matter.
        const [account, secret] = await Promise.all([
          getManagedAccount().catch(() => null),
          getUnlockableRecoverySecret(),
        ]);

        if (cancelled) return;

        if (secret) {
          setRestore({
            phase: 'ready',
            secret,
            email: account
              ? accountAddress(account)
              : (secret.owner_address ?? secret.owner_email),
          });

          if (
            account?.email === secret.owner_email &&
            hasAssistedWrapper(secret)
          ) {
            setAssistedUnlock('trying');

            try {
              const plaintext = await decryptEnvelopeWithAssisted(secret);
              if (cancelled) return;
              await handleSignInWithSecret(plaintext);
            } catch (err) {
              if (!cancelled) {
                setAssistedUnlock(
                  err instanceof FreshSignInRequiredError
                    ? 'needs-sign-in'
                    : 'idle',
                );
              }
            }
          }

          return;
        }

        setRestore(
          account?.email
            ? { phase: 'no-backup', email: accountAddress(account) }
            : { phase: 'no-session' },
        );
      } catch {
        if (!cancelled) setRestore({ phase: 'no-session' });
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [step, restoreAttempt]);

  /**
   * Unlock a backup with its passkey — one prompt, no typing. Returns whether
   * it worked, so callers can fall through to another route if not.
   */
  async function unlockWithPasskey(backup: RecoverySecret): Promise<boolean> {
    if (loading) return false;

    setLoading(true);
    setError(undefined);

    try {
      const secret = await decryptEnvelopeWithPasskey(backup);
      await handleSignInWithSecret(secret);

      return true;
    } catch (err) {
      setError(
        err instanceof Error
          ? err
          : new Error('Could not unlock with your passkey.'),
      );

      return false;
    } finally {
      setLoading(false);
    }
  }

  async function handleRestoreWithPasskey() {
    if (restore.phase !== 'ready') return;
    await unlockWithPasskey(restore.secret);
  }

  /**
   * "Sign in" tries the passkey straight away when this device holds exactly
   * one account, so the common case is a single click → fingerprint → in,
   * with no intermediate screen. Several accounts means we can't know which,
   * so the sign-in step shows a picker instead of guessing. Anything else (no
   * passkey here, cancelled, wrong device) falls through to the form, which
   * still offers the passkey as an explicit retry.
   *
   * The cache is read at click time: WebAuthn needs a transient user gesture,
   * so the prompt has to be raised from inside the handler.
   */
  async function handleSignInClick() {
    setError(undefined);
    setSecretValue('');

    const unlockable = readUnlockableCachedBackups();

    if (unlockable.length === 1 && (await unlockWithPasskey(unlockable[0]))) {
      return;
    }

    setStep('signin');
  }

  async function handleRestore(e: FormEvent) {
    e.preventDefault();

    if (restore.phase !== 'ready' || loading) return;

    const input = restoreCodeInput.trim();

    if (!input) return;

    setLoading(true);
    setError(undefined);

    try {
      const isEnvelopeV2 = restore.secret.format_version >= 2;
      // v2 codes are normalized inside decryptEnvelopeV2, so the raw input is
      // passed through; a v1 password is used verbatim (it's user-chosen).
      const secret = isEnvelopeV2
        ? await decryptEnvelopeV2(restore.secret, input)
        : await decryptRecoverySecret(restore.secret, input);

      if (isEnvelopeV2) {
        // Reuse the normal sign-in path: parses the secret, sets the agent,
        // and navigates to the user's home drive.
        await handleSignInWithSecret(secret);

        return;
      }

      // v1 backup, successfully decrypted: nudge it onto envelope v2 now
      // that we have the plaintext secret in hand. Best-effort — a failure
      // here must never block the sign-in that already succeeded, since the
      // v1 backup stays readable indefinitely either way.
      try {
        const { recoveryCode } = await upgradeToEnvelopeV2({
          secret,
          agentSubject: restore.secret.agent_subject,
          driveSubject: restore.secret.drive_subject,
          userName: restore.email,
        });

        if (recoveryCode === null) {
          // Upgraded onto a passkey — there's nothing to show, so don't
          // interrupt the restore with a screen that says so.
          await handleSignInWithSecret(secret);

          return;
        }

        setUpgradedCode(recoveryCode);
        setSecretAfterUpgrade(secret);
        setStep('restore-upgraded');
      } catch {
        await handleSignInWithSecret(secret);
      }
    } catch (err) {
      setError(
        err instanceof Error
          ? err
          : new Error('Could not restore your account.'),
      );
    } finally {
      setLoading(false);
    }
  }

  /**
   * Sign in as soon as the field holds a usable secret.
   *
   * A secret either parses or it doesn't, so a Continue button only adds a
   * click. Validation is silent while typing — every prefix of a valid secret
   * is invalid, and flashing an error on each keystroke is noise. The error
   * appears on blur or Enter, once the user has actually finished.
   *
   * Note this is parse-based, not timer-based: an earlier version auto-submitted
   * 150ms after any change, which fired spurious attempts mid-typing and raced
   * the button. Nothing here is scheduled.
   */
  async function trySecret(value: string, showError = false) {
    const trimmed = value.trim();

    if (loading) return;

    if (!trimmed) {
      setSecretError(undefined);

      return;
    }

    try {
      await Agent.fromSecret(trimmed);
    } catch {
      setSecretError(
        showError ? 'That doesn’t look like a valid agent secret.' : undefined,
      );

      return;
    }

    setSecretError(undefined);
    await handleSignInWithSecret(trimmed);
  }

  async function handleSubmitSignIn(e: FormEvent) {
    e.preventDefault();
    await trySecret(secretValue, true);
  }

  return (
    <Shell>
      {step === 'welcome' && !createTarget ? (
        <div role='status' aria-label='Loading account'>
          <Spinner size='4rem' />
        </div>
      ) : step === 'opening-workspace' ? (
        <Swap key='opening-workspace'>
          <OnboardingWrap>
            <OnboardingCard>
              <WorkspaceLoading stage={workspaceStage} />
            </OnboardingCard>
          </OnboardingWrap>
        </Swap>
      ) : step === 'welcome' ? (
        <WelcomeSwap key='welcome'>
          <WelcomeStack>
            <VisuallyHiddenH1 key='heading'>{PRODUCT_NAME}</VisuallyHiddenH1>
            {/* alt='' because the heading above already names the app. */}
            <AtomicServerLogo key='logo' alt='' />
            <ButtonStack key='buttons'>
              {/* A node with an owner has nowhere to put a new account, so
                  offering one would be offering a dead end. Sign in and invites
                  still work, and are what someone arriving here actually needs.
                  Guarded rather than always-rendered: on every other node this
                  subtree must not exist at all. */}
              {createTarget?.kind === 'unavailable' ? (
                <CardSubtitle key='owned'>
                  This server is run by one person for their own data. You can
                  sign in, or open a drive you were invited to.
                </CardSubtitle>
              ) : (
                <CtaButton
                  key='create'
                  type='button'
                  disabled={!createTarget}
                  onClick={() => {
                    // Belt and braces with `disabled`: the button is unclickable
                    // until `/server` answers, so this only guards a
                    // programmatic call.
                    if (!createTarget) return;

                    // Hosted build or managed node → create the account on the
                    // portal (email verification). FOSS node → local identity.
                    if (createTarget.kind === 'portal') {
                      const url = safePortalUrl(createTarget.url);

                      if (url) window.location.assign(url);
                    } else {
                      setStep('create');
                    }
                  }}
                >
                  Create account
                </CtaButton>
              )}
              {/* No account-less create path in a hosted build. It minted a
                  second identity that the portal then swapped away the
                  moment its owner signed in with an email that already had
                  one (staging, 2026-09-03). One email, one identity: the
                  hosted welcome creates through the portal or signs in with
                  an existing secret — nothing in between. A FOSS build's
                  "Create account" is the local path, and someone with their
                  own secret has Sign in below. */}
              <CtaButton
                key='signin'
                type='button'
                subtle
                disabled={loading}
                onClick={handleSignInClick}
              >
                {loading ? 'Waiting for your passkey…' : 'Sign in'}
              </CtaButton>
              <CtaButton
                key='demo'
                type='button'
                subtle
                onClick={() => {
                  // No account needed: the demo mints a throwaway
                  // guest agent and runs entirely on this device.
                  navigate(paths.demo);
                }}
              >
                Try the live demo
              </CtaButton>
            </ButtonStack>
            {/* Below the buttons on purpose: what this node offers comes
                first, and this is the consolation for someone it cannot
                help. Plain links, no icon — an aside, not a third choice
                competing with Sign in. */}
            {createTarget?.kind === 'unavailable' ? (
              <OwnedElsewhere key='elsewhere'>
                Want a server of your own?{' '}
                <PlainExternalLink
                  href='https://atomic.place'
                  target='_blank'
                  rel='noreferrer'
                >
                  Get one hosted
                </PlainExternalLink>{' '}
                or{' '}
                <PlainExternalLink
                  href='https://github.com/atomicdata-dev/atomic-server'
                  target='_blank'
                  rel='noreferrer'
                >
                  run it yourself
                </PlainExternalLink>
                .
              </OwnedElsewhere>
            ) : null}
            {error ? (
              <CardError key='error' role='alert'>
                {error.message}
              </CardError>
            ) : null}
          </WelcomeStack>
        </WelcomeSwap>
      ) : step === 'signin' ? (
        <Swap key='signin'>
          <OnboardingWrap>
            <OnboardingCard key='card'>
              <Column gap='1rem'>
                <CardTitle key='title'>
                  {nextDrive ? 'Unlock this drive' : 'Sign in'}
                </CardTitle>
                {nextDrive && !restoreUnlock.showPasskey ? (
                  <CardSubtitle key='subtitle'>
                    {restore.phase === 'no-backup' ? (
                      <>
                        You’re signed in as {restore.email}, but this browser
                        needs your account key to open this private drive. Paste
                        your saved agent secret below. No account recovery
                        backup is available.
                      </>
                    ) : (
                      <>
                        Enter your agent secret to unlock this drive on this
                        device.
                      </>
                    )}
                  </CardSubtitle>
                ) : null}

                {accountSignIn()}

                {/* Several accounts on this machine: ask which, rather than
                    guessing and raising a prompt for the wrong one. */}
                {knownAccounts.length > 1 ? (
                  <Column key='accounts' gap='0.75rem'>
                    <CardSubtitle>Continue as</CardSubtitle>
                    {error ? (
                      <CardError role='alert'>{error.message}</CardError>
                    ) : null}
                    {knownAccounts.map(account => {
                      const address =
                        account.owner_address ?? account.owner_email;
                      // The same address twice is two identities of one
                      // account, from before the newer backup replaced the
                      // older. Say which is which, and let the stale one go.
                      const repeated =
                        knownAccounts.filter(
                          other =>
                            (other.owner_address ?? other.owner_email) ===
                            address,
                        ).length > 1;

                      return (
                        <AccountChoice key={account.agent_subject}>
                          <Button
                            type='button'
                            subtle
                            disabled={loading}
                            onClick={() => unlockWithPasskey(account)}
                            data-test='account-choice'
                          >
                            <AccountLabel>
                              {address}
                              {repeated && (
                                <AccountDetail>
                                  {`Saved ${new Date(account.updated_at || account.created_at).toLocaleDateString()}, identity …${account.agent_subject.slice(-6)}`}
                                </AccountDetail>
                              )}
                            </AccountLabel>
                          </Button>
                          <IconButton
                            title={`Forget ${address} on this device`}
                            disabled={loading}
                            onClick={() => {
                              forgetCachedRecoverySecret(account.agent_subject);
                              setKnownAccounts(readUnlockableCachedBackups());
                            }}
                          >
                            <FaXmark />
                          </IconButton>
                        </AccountChoice>
                      );
                    })}
                    <OtherWaysLabel>or sign in another way</OtherWaysLabel>
                  </Column>
                ) : null}

                {/* A backup this browser can open right now: lead with it.
                    The agent secret stays available below, but it's the
                    advanced path — see the recovery hierarchy in
                    planning/BACKUP_SECURITY.md. */}
                {knownAccounts.length <= 1 && restoreUnlock.showPasskey ? (
                  <Column key='passkey' gap='0.75rem'>
                    <CardSubtitle>
                      Use your fingerprint, face, or screen lock.
                    </CardSubtitle>
                    {error ? (
                      <CardError role='alert'>{error.message}</CardError>
                    ) : null}
                    <Button
                      type='button'
                      disabled={loading}
                      onClick={handleRestoreWithPasskey}
                    >
                      {loading
                        ? 'Waiting for your passkey…'
                        : 'Unlock with your passkey'}
                    </Button>
                    {restoreUnlock.hasCode ? (
                      <Button
                        type='button'
                        subtle
                        disabled={loading}
                        onClick={() => {
                          setError(undefined);
                          setPreferCodeEntry(true);
                          setStep('restore');
                        }}
                      >
                        Use a recovery code instead
                      </Button>
                    ) : (
                      <PasskeyOnlyHint />
                    )}
                    <OtherWaysLabel>or sign in another way</OtherWaysLabel>
                  </Column>
                ) : null}

                <form key='form' onSubmit={handleSubmitSignIn}>
                  <Column gap='1rem'>
                    <InputWrapper key='input' hasPrefix>
                      <FaKey />
                      <InputStyled
                        value={secretValue}
                        // A secret either parses or it doesn't, so there's
                        // nothing to confirm with a button: signing in the
                        // moment it's valid covers typing and pasting alike.
                        onChange={e => {
                          setSecretValue(e.target.value);
                          void trySecret(e.target.value);
                        }}
                        onBlur={() => void trySecret(secretValue, true)}
                        type='password'
                        name='secret'
                        autoComplete='current-password'
                        spellCheck={false}
                        placeholder={
                          loading ? 'Signing in…' : 'Paste your agent secret'
                        }
                        aria-label='Agent secret'
                        disabled={loading}
                        autoFocus={
                          !restoreUnlock.showPasskey &&
                          knownAccounts.length <= 1
                        }
                      />
                    </InputWrapper>
                    {/* Rendered by the passkey/account block above when one of
                        those is shown, so it never appears twice. */}
                    {(secretError || error) &&
                    !restoreUnlock.showPasskey &&
                    knownAccounts.length <= 1 ? (
                      <CardError key='error' role='alert'>
                        {secretError ?? error?.message}
                      </CardError>
                    ) : null}
                    {/* Native installs need a way to link the portal before
                        the backup check can succeed. Once linked, the restore
                        step checks whether this account has a backup. */}
                    {knownAccounts.length === 0 &&
                    knownPortalUrl &&
                    restore.phase === 'ready' ? (
                      <Button
                        key='forgot'
                        type='button'
                        subtle
                        onClick={() => {
                          setError(undefined);
                          setSecretError(undefined);
                          setRestoreCodeInput('');
                          setPreferCodeEntry(false);
                          setStep('restore');
                        }}
                      >
                        {`Forgot it? Restore from ${PRODUCT_NAME}`}
                      </Button>
                    ) : null}
                    {nextDrive && !returnToPortal ? (
                      // The sign-in guard (ErrorPage → here with `next`) can't
                      // tell a returning user on a new device from a total
                      // stranger who's never had an account — both hit an
                      // unauthorized private resource the same way. Without
                      // this, a stranger has no visible path forward besides
                      // "Back" (not obvious it leads to account creation).
                      <Button
                        key='create'
                        type='button'
                        subtle
                        disabled={
                          !createTarget || createTarget.kind === 'unavailable'
                        }
                        onClick={() => {
                          if (
                            !createTarget ||
                            createTarget.kind === 'unavailable'
                          )
                            return;
                          setError(undefined);

                          if (createTarget.kind === 'portal') {
                            const url = safePortalUrl(createTarget.url);

                            if (url) {
                              if (isRunningInTauri()) void openExternal(url);
                              else window.location.assign(url);
                            }
                          } else {
                            setStep('create');
                          }
                        }}
                      >
                        Create account
                      </Button>
                    ) : null}
                  </Column>
                </form>
              </Column>
            </OnboardingCard>
            <FooterBar key='footer'>
              <Button
                key='back'
                type='button'
                subtle
                onClick={() => {
                  setError(undefined);
                  setSecretValue('');

                  if (returnToPortal && knownPortalUrl && !isRunningInTauri()) {
                    window.location.assign(
                      new URL('/dashboard', knownPortalUrl).toString(),
                    );
                  } else if (isHostedDistribution() && knownPortalUrl) {
                    // No welcome step in a hosted build; Back leaves for the portal.
                    window.location.assign(knownPortalUrl);
                  } else {
                    setStep('welcome');
                  }
                }}
              >
                <BackLabel>
                  <FaArrowLeft key='icon' aria-hidden />
                  Back
                </BackLabel>
              </Button>
              <StepDotsSlot key='dots' ref={stepDotsSlotRef} />
            </FooterBar>
          </OnboardingWrap>
        </Swap>
      ) : step === 'connect-device' ? (
        <Swap key='connect-device'>
          <ConnectDeviceStep
            drive={missingDrive}
            vaultReason={missingDriveVaultReason}
            portalUrl={knownPortalUrl}
            onConnected={target => {
              setDrive(target);
              navigate(constructOpenURL(target));
            }}
            onSkip={() => {
              // A deferral, not a dead end: the Sync page offers the same
              // route from its "data is on another device" card.
              //
              // Never into the drive itself, even though we can name it —
              // that is the empty shell this step exists to keep people out
              // of, and arriving in it by pressing Skip makes it look like
              // the workspace came back empty.
              navigate(paths.sync);
            }}
          />
        </Swap>
      ) : step === 'restore' ? (
        <Swap key='restore'>
          <OnboardingWrap>
            <OnboardingCard key='card'>
              <Column gap='1rem'>
                <CardTitle key='title'>Restore account</CardTitle>
                {/* Signed out, this is the whole step: the portal's options,
                    finished in the system browser where this app cannot hold
                    the account cookie. */}
                {accountSignIn()}
                {restore.phase === 'checking' ? (
                  <p key='checking'>{`Checking your ${PRODUCT_NAME} account…`}</p>
                ) : restore.phase === 'no-session' ? null : restore.phase ===
                  'no-backup' ? (
                  inviteToken ? (
                    // The portal sends an invitee here whenever it cannot rule
                    // out an earlier identity. With nothing to restore, the
                    // invitation still wants an account to land in.
                    <Column key='no-backup-invite' gap='0.75rem'>
                      <p key='copy'>
                        {`There is nothing to restore for ${restore.email} yet. Create your account to accept the invitation.`}
                      </p>
                      <Button
                        key='create'
                        type='button'
                        onClick={() => {
                          const url = new URL(window.location.href);
                          url.searchParams.set('from_portal', 'true');
                          url.searchParams.set('email', restore.email);
                          // A reload, because the managed create flow is read
                          // from the URL on mount.
                          window.location.assign(url.toString());
                        }}
                      >
                        Create account and accept
                      </Button>
                    </Column>
                  ) : (
                    <p key='no-backup'>
                      No recovery backup was found for {restore.email}. Account
                      recovery only works if you enabled it earlier.
                    </p>
                  )
                ) : restoreUnlock.showPasskey ? (
                  <Column key='ready-passkey' gap='1rem'>
                    <p key='copy'>
                      Unlock {restore.email} with your fingerprint, face, or
                      screen lock.
                    </p>
                    {error ? (
                      <CardError key='error' role='alert'>
                        {error.message}
                      </CardError>
                    ) : null}
                    <Button
                      key='passkey'
                      type='button'
                      disabled={loading}
                      onClick={handleRestoreWithPasskey}
                    >
                      {loading
                        ? 'Waiting for your passkey…'
                        : 'Unlock with your passkey'}
                    </Button>
                    {restoreUnlock.hasCode ? (
                      <Button
                        key='use-code'
                        type='button'
                        subtle
                        disabled={loading}
                        onClick={() => {
                          setError(undefined);
                          setPreferCodeEntry(true);
                        }}
                      >
                        Use a recovery code instead
                      </Button>
                    ) : (
                      <PasskeyOnlyHint key='passkey-only' />
                    )}
                  </Column>
                ) : (
                  <form key='ready' onSubmit={handleRestore}>
                    <Column gap='1rem'>
                      <p key='copy'>
                        {restore.secret.format_version >= 2
                          ? `Enter the recovery code you saved for ${restore.email}.`
                          : `Enter the recovery password you set for ${restore.email}.`}
                      </p>
                      <InputWrapper key='input' hasPrefix>
                        <FaKey />
                        <InputStyled
                          value={restoreCodeInput}
                          onChange={e => setRestoreCodeInput(e.target.value)}
                          type='password'
                          autoComplete='current-password'
                          placeholder={
                            restore.secret.format_version >= 2
                              ? 'Recovery code'
                              : 'Recovery password'
                          }
                          aria-label={
                            restore.secret.format_version >= 2
                              ? 'Recovery code'
                              : 'Recovery password'
                          }
                          autoFocus
                        />
                      </InputWrapper>
                      {error ? (
                        <CardError key='error' role='alert'>
                          {error.message}
                        </CardError>
                      ) : null}
                      <Button
                        key='submit'
                        type='submit'
                        disabled={loading || !restoreCodeInput.trim()}
                      >
                        {loading ? 'Restoring…' : 'Restore & sign in'}
                      </Button>
                      {restoreUnlock.hasPasskey ? (
                        <Button
                          key='use-passkey'
                          type='button'
                          subtle
                          disabled={loading}
                          onClick={() => {
                            setError(undefined);
                            setPreferCodeEntry(false);
                          }}
                        >
                          Use your passkey instead
                        </Button>
                      ) : null}
                    </Column>
                  </form>
                )}
              </Column>
            </OnboardingCard>
            <FooterBar key='footer'>
              <Button
                key='back'
                type='button'
                subtle
                onClick={() => {
                  setError(undefined);
                  setRestoreCodeInput('');
                  setStep('signin');
                }}
              >
                <BackLabel>
                  <FaArrowLeft key='icon' aria-hidden />
                  Back
                </BackLabel>
              </Button>
              <StepDotsSlot key='dots' ref={stepDotsSlotRef} />
            </FooterBar>
          </OnboardingWrap>
        </Swap>
      ) : step === 'secret-conflict' && secretConflict ? (
        <Swap key='secret-conflict'>
          <OnboardingWrap>
            <OnboardingCard key='card'>
              <Column gap='1rem'>
                <CardTitle key='title'>
                  This secret is for a different account
                </CardTitle>
                <p key='copy'>
                  You&apos;re signed in as {secretConflict.email}, but the
                  secret you entered opens another agent. Using it signs you out
                  of {secretConflict.email} on {PRODUCT_NAME}.
                </p>
                <AgentList key='agents'>
                  <dt>{secretConflict.email}</dt>
                  <dd>{shortDid(secretConflict.accountAgent)}</dd>
                  <dt>This secret</dt>
                  <dd>{shortDid(secretConflict.secretAgent)}</dd>
                </AgentList>
                <Button
                  key='keep'
                  type='button'
                  disabled={loading}
                  data-test='secret-conflict-keep'
                  onClick={() => {
                    setSecretConflict(null);
                    setSecretValue('');
                    setStep('signin');
                  }}
                >
                  {`Stay signed in as ${secretConflict.email}`}
                </Button>
                <Button
                  key='replace'
                  type='button'
                  subtle
                  disabled={loading}
                  data-test='secret-conflict-replace'
                  onClick={() =>
                    void handleSignInWithSecret(
                      secretConflict.secret,
                      secretConflict,
                    )
                  }
                >
                  Use this secret and sign out
                </Button>
              </Column>
            </OnboardingCard>
          </OnboardingWrap>
        </Swap>
      ) : step === 'restore-upgraded' ? (
        <Swap key='restore-upgraded'>
          <OnboardingWrap>
            <OnboardingCard key='card'>
              <Column gap='1rem'>
                <CardTitle key='title'>Save your new recovery code</CardTitle>
                <p key='copy'>
                  We&apos;ve replaced your old recovery password with a stronger
                  generated code. Keep it somewhere safe — you&apos;ll need it,
                  plus your email, to get back in. We can&apos;t show it again,
                  but you can generate a new one from Settings any time.
                </p>
                <CodeBlock
                  key='code'
                  className='recovery-code-block'
                  wordWrap
                  content={upgradedCode ?? ''}
                  onCopy={() => setUpgradedCodeSaved(true)}
                />
                {upgradedCodeSaved ? (
                  <Button
                    key='continue'
                    type='button'
                    onClick={() => {
                      if (secretAfterUpgrade) {
                        void handleSignInWithSecret(secretAfterUpgrade);
                      }
                    }}
                  >
                    Yes, I&apos;ve stored it safely
                  </Button>
                ) : (
                  <Button key='disabled' disabled>
                    Copy the code to continue
                  </Button>
                )}
              </Column>
            </OnboardingCard>
            <FooterBar key='footer'>
              <StepDotsSlot key='dots' ref={stepDotsSlotRef} />
            </FooterBar>
          </OnboardingWrap>
        </Swap>
      ) : (
        <Swap key='create'>
          <OnboardingWrap>
            <OnboardingCard key='card'>
              <Column gap='1.5rem'>
                {fromManaged && !managedReady ? (
                  <p>Setting up your account…</p>
                ) : (
                  <NewIdentitySection
                    autoStart
                    navigateToDrive={!inviteToken && !pendingTemplate}
                    // Already saved and confirmed on the portal.
                    verifySecret={!presetKeys}
                    presetKeys={presetKeys}
                    stepIndicatorPortal={stepDotsSlotRef.current}
                    defaultProfileName={managedUsername}
                    offerRecoveryBackup={fromManaged}
                    onBackupWithPasskey={
                      fromManaged ? backupWithPasskey : undefined
                    }
                    onBackupWithCode={fromManaged ? backupWithCode : undefined}
                    onBackupWithAccount={
                      fromManaged ? backupWithAccount : undefined
                    }
                    onAfterCreate={
                      fromManaged ? enableEncryptedBackup : undefined
                    }
                    onDone={() => {
                      if (inviteToken) navigate(resumeInviteUrl(inviteToken));
                      else if (pendingTemplate)
                        navigate(pendingTemplateUrl(pendingTemplate));
                    }}
                  />
                )}
              </Column>
            </OnboardingCard>
            <FooterBar key='footer'>
              <Button
                key='back'
                subtle
                type='button'
                onClick={() => {
                  if (knownPortalUrl && !isRunningInTauri()) {
                    window.location.assign(
                      new URL('/dashboard', knownPortalUrl).toString(),
                    );
                  } else {
                    setStep('welcome');
                  }
                }}
              >
                <BackLabel>
                  <FaArrowLeft key='icon' aria-hidden />
                  Back
                </BackLabel>
              </Button>
              <StepDotsSlot key='dots' ref={stepDotsSlotRef} />
            </FooterBar>
          </OnboardingWrap>
        </Swap>
      )}
    </Shell>
  );
}

const Swap = styled.div`
  width: 100%;
  animation: ${swapIn} 220ms ease-out;

  /* A packaged macOS WebView can leave entry animations at time zero while
     its window is not foregrounded. That makes the whole flow transparent. */
  ${isRunningInTauri() && 'animation: none;'}

  @media (prefers-reduced-motion: reduce) {
    animation: none;
  }
`;

/* The one step that is a landing, not a form: center it in the viewport.
   Auto margins (not justify-content) so a phone too short for it still
   scrolls from the top instead of clipping the logo. Doubled specificity to
   beat Shell's top-aligning margin reset for its children. */
const WelcomeSwap = styled(Swap)`
  && {
    margin-block: auto;
  }
`;

const WelcomeStack = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: ${p => p.theme.size(9)};
  width: 100%;
  max-width: 22rem;
  margin-inline: auto;
  text-align: center;
`;

const ButtonStack = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  width: 100%;
`;

const VisuallyHiddenH1 = styled.h1`
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border-width: 0;
`;

/**
 * The inline lockup, not an `<img>` of /logo.svg: that file carries an 8px
 * white keyline for placement on photos, which a dark-mode
 * `filter: brightness(0) invert(1)` cannot undo — it bloats the glyphs, closes
 * their counters and flattens the orb's gradient to white. The component inks
 * itself from the dark-mode setting instead.
 */
const AtomicServerLogo = styled(Logo)`
  width: 100%;
  max-width: min(30rem, 92vw);
  height: auto;
  display: block;
  margin-inline: auto;

  @media (min-width: 56em) {
    margin-inline: 0;
  }
`;

/** Separates the offered passkey from the advanced agent-secret path below. */
const OwnedElsewhere = styled.p`
  margin: 0;
  width: 100%;
  text-align: center;
  /* pretty, not balance: balancing squeezed this to half the available
     width and split a link across two lines. */
  text-wrap: pretty;
  color: ${p => p.theme.colors.textLight};
  font-size: 0.85rem;
`;

/**
 * Shown under the passkey button when the backup has no recovery-code
 * wrapper — the shape onboarding leaves behind by default. Without this the
 * code button simply did not render, and someone on a browser their passkey
 * never synced to (Firefox next to Safari on the same laptop) was left with a
 * passkey prompt that finds nothing and a field for an agent secret they were
 * never shown. Says where the way out is, since the guard itself cannot add a
 * code: that is a write to the backup, which needs the passkey that is
 * missing here.
 */
function PasskeyOnlyHint(): React.JSX.Element {
  return (
    <OwnedElsewhere data-testid='passkey-only-hint'>
      Only your passkey opens this account. If it isn&apos;t on this device,
      unlock on the one where you set it up and add a recovery code under
      Settings — that gets you in anywhere.
    </OwnedElsewhere>
  );
}

const PlainExternalLink = styled.a`
  color: ${p => p.theme.colors.main};
  text-decoration: underline;
  /* A link that reads as one thing should wrap as one thing. */
  white-space: nowrap;
`;

/** The two agents a secret conflict is about, so the choice is concrete. */
const AgentList = styled.dl`
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 0.25rem 1rem;
  margin: 0;
  font-size: 0.85rem;

  & dt {
    color: ${p => p.theme.colors.textLight};
  }

  & dd {
    margin: 0;
    font-family: monospace;
    overflow-wrap: anywhere;
  }
`;

const AccountChoice = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;

  & > button:first-child {
    flex: 1;
    min-width: 0;
  }
`;

const AccountLabel = styled.span`
  display: flex;
  flex-direction: column;
  align-items: center;
  min-width: 0;
  overflow-wrap: anywhere;
`;

const AccountDetail = styled.small`
  display: block;
  color: ${p => p.theme.colors.textLight};
`;

const OtherWaysLabel = styled.span`
  display: flex;
  align-items: center;
  gap: 0.75rem;
  color: ${p => p.theme.colors.textLight};
  font-size: 0.85rem;

  &::before,
  &::after {
    content: '';
    flex: 1;
    border-top: 1px solid ${p => p.theme.colors.bg2};
  }
`;

const StepDotsSlot = styled.div`
  min-height: 1.25rem;

  & [data-step-dots='true'] {
    display: flex;
    justify-content: center;
    gap: 6px;
  }
`;

/** The `#secret=` the portal hands over after a secret sign-up, removed from
 * the URL as it is read. */
function takeSecretFragment():
  | { privateKey: string; agentSubject: string }
  | undefined {
  const secret = new URLSearchParams(window.location.hash.slice(1)).get(
    'secret',
  );

  if (!secret) return undefined;

  window.history.replaceState(
    window.history.state,
    '',
    window.location.pathname + window.location.search,
  );

  try {
    const { privateKey, subject } = decodeSecret(secret);

    return subject ? { privateKey, agentSubject: subject } : undefined;
  } catch {
    return undefined;
  }
}
