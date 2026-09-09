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
import { Agent } from '@tomic/lib';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';
import { useWelcomeLayoutEffect } from '../../hooks/useWelcomeLayoutEffect';
import { useSettings } from '../../helpers/AppSettings';
import { saveAgentToIDB } from '../../helpers/agentStorage';
import { beat } from '../../helpers/deviceLock';
import { fetchPrivateDriveSubject } from '../../helpers/privateDrive';
import { deviceHasDriveData } from '../../helpers/driveData';
import { withDeadline } from '../../helpers/withDeadline';
import { constructOpenURL } from '../../helpers/navigation';
import { paths } from '../../routes/paths';
import { Button } from '../../components/Button';
import { Column } from '../../components/Row';
import { NewIdentitySection } from '../../components/NewIdentitySection';
import { getManagedAccount } from '../../helpers/managed/session';
import { getManagedPortalUrl } from '../../helpers/managed/cloudSync';
import { safePortalUrl } from '../../helpers/managed/api';
import {
  fetchManagedInfo,
  accountCreationTarget,
  type AccountCreationTarget,
} from '../../helpers/managedServer';
import {
  ensureVaultBackup,
  restoreFromVault,
} from '../../helpers/managed/vaultAutoBackup';
import { isOriginWithoutNode } from '../../helpers/originNode';
import {
  buildEnvelopeV2,
  buildEnvelopeWithPasskeyAndCode,
  saveRecoverySecret,
  getRecoverySecret,
  getUnlockableRecoverySecret,
  readUnlockableCachedBackups,
  decryptRecoverySecret,
  decryptEnvelopeV2,
  decryptEnvelopeWithPasskey,
  envelopeWrapperKinds,
  upgradeToEnvelopeV2,
  type RecoverySecret,
} from '../../helpers/managed/recovery';
import { CodeBlock } from '../../components/CodeBlock';
import { InputStyled, InputWrapper } from '../../components/forms/InputStyles';
import { FaArrowLeft, FaKey } from 'react-icons/fa6';
import { Logo } from '../../components/Logo';
import { ConnectDeviceStep } from './ConnectDeviceStep';
import { LinkProviderPanel } from '../../components/Vault/LinkProviderPanel';
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
  const { setAgent, setDrive, baseURL } = useSettings();
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
  const [knownPortalUrl, setKnownPortalUrl] = useState<string | null>(null);

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
  // A sign-in guard (clicking a drive you're not signed in for) sends the user
  // here with `next` carrying that drive's subject, so we open straight to the
  // sign-in step and return them to that drive afterwards (not their home).
  const nextDrive =
    new URLSearchParams(window.location.search).get('next') || undefined;
  const [step, setStep] = useState<Step>(
    fromManaged ? 'create' : nextDrive ? 'signin' : initialStep,
  );
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
          setManagedUsername(account.email.split('@')[0]);
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

  // ─── Restore ("Forgot your secret?") ─────────────────────────────────────
  const [restore, setRestore] = useState<RestoreState>({ phase: 'checking' });
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
            email: account?.email ?? secret.owner_email,
          });

          return;
        }

        setRestore(
          account?.email
            ? { phase: 'no-backup', email: account.email }
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
   * Pasting a secret is an explicit "I am this agent". If the control-plane
   * session belongs to an account whose backup names a *different* agent, the
   * reconcile gate would bounce the user straight back here
   * (IDENTITY_RECONCILE_SCENARIOS.md scenario 4) — silently undoing what they
   * just did, and looking exactly like "I can't sign in".
   *
   * That gate exists to converge a *stray* local agent at boot, not to
   * override a deliberate action. So the stale thing here is the portal
   * session: end it, and let the secret win.
   */
  async function releaseConflictingPortalSession(agentSubject: string) {
    try {
      const stored = await getRecoverySecret();

      if (stored && stored.agent_subject !== agentSubject) {
        clearManagedAccountBinding();
        await logoutManagedSession();
        toast(
          'Signed out of your account here — that secret belongs to a different one.',
        );
      }
    } catch {
      // No session, or the control plane is unreachable: nothing to release.
    }
  }

  async function handleSignInWithSecret(secret: string) {
    setLoading(true);
    setError(undefined);

    try {
      const newAgent = await Agent.fromSecret(secret);
      setWorkspaceStage('identity');
      setStep('opening-workspace');
      setAgent(newAgent);
      await saveAgentToIDB(secret);
      // However they got in — passkey, code, or secret — the device is open
      // again, so start the clock fresh (see deviceLock.ts).
      beat();

      if (newAgent.subject) {
        await withDeadline(
          releaseConflictingPortalSession(newAgent.subject),
          SIGN_IN_LOOKUP_TIMEOUT_MS,
          undefined,
        );
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

      // A secret restores who you are, not what you have. So the app only
      // opens once the workspace is here to read: opening one we cannot read
      // shows an empty shell wearing its name, which reads as data loss.
      //
      // Asked before anything writes the drive, deliberately. Materializing it
      // first — which is what this flow used to do — makes every "do I have my
      // data?" check answer yes about data the device does not have.
      const canRead = (subject: string) =>
        withDeadline(
          deviceHasDriveData(store, subject),
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

      if (!hasData && target) {
        setWorkspaceStage('backup');
        const restored = await withDeadline(
          restoreFromVault(store, target),
          VAULT_RESTORE_TIMEOUT_MS,
          { status: 'no-backup' as const, reason: 'timed out' },
        );

        if (restored.status === 'restored') {
          hasData = await canRead(target);
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

      // Name the account's drive even when its data hasn't arrived: it is
      // derived from the key, so it is the one place this identity can write
      // right away, and the Sync page says "your data is on another device"
      // about *that* drive, which is true and useful. Only when the drive
      // cannot be named at all is no drive the honest answer — the value here
      // otherwise falls back to whatever was last open, or to the default,
      // which is the server's own root. Showing that as your workspace is how
      // signing in ends with somebody else's data on screen.
      setDrive(target ?? '');

      if (hasData) {
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

        navigate(constructOpenURL(target!));
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
      {step === 'opening-workspace' ? (
        <Swap key='opening-workspace'>
          <OnboardingWrap>
            <OnboardingCard>
              <WorkspaceLoading stage={workspaceStage} />
            </OnboardingCard>
          </OnboardingWrap>
        </Swap>
      ) : step === 'welcome' ? (
        <Swap key='welcome'>
          <WelcomeStack>
            <VisuallyHiddenH1 key='heading'>AtomicServer</VisuallyHiddenH1>
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
                  href='https://atomicserver.eu'
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
        </Swap>
      ) : step === 'signin' ? (
        <Swap key='signin'>
          <OnboardingWrap>
            <OnboardingCard key='card'>
              <Column gap='1rem'>
                <CardTitle key='title'>
                  {nextDrive ? 'Sign in to access this drive' : 'Sign in'}
                </CardTitle>
                {nextDrive && !restoreUnlock.showPasskey ? (
                  <CardSubtitle key='subtitle'>
                    Enter your agent secret to unlock this drive on this device.
                  </CardSubtitle>
                ) : null}

                {/* Several accounts on this machine: ask which, rather than
                    guessing and raising a prompt for the wrong one. */}
                {knownAccounts.length > 1 ? (
                  <Column key='accounts' gap='0.75rem'>
                    <CardSubtitle>Continue as</CardSubtitle>
                    {error ? (
                      <CardError role='alert'>{error.message}</CardError>
                    ) : null}
                    {knownAccounts.map(account => (
                      <Button
                        key={account.agent_subject}
                        type='button'
                        subtle
                        disabled={loading}
                        onClick={() => unlockWithPasskey(account)}
                        data-test='account-choice'
                      >
                        {account.owner_email}
                      </Button>
                    ))}
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
                    {/* Hidden once accounts are listed above: that picker is
                        already the "recover via my account" route, and a
                        second door to the same room just adds a button. Also
                        hidden when no portal is known — a source build with
                        nothing to restore from — because the step behind it
                        can then only say "sign in first" with nowhere to. */}
                    {knownAccounts.length === 0 && knownPortalUrl ? (
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
                    {nextDrive ? (
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

                            if (url) window.location.assign(url);
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
                  setStep('welcome');
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
                {restore.phase === 'checking' ? (
                  <p key='checking'>{`Checking your ${PRODUCT_NAME} account…`}</p>
                ) : restore.phase === 'no-session' ? (
                  // Two ways to get a session, and only one works per client.
                  // A page on the portal's own site signs in there and comes
                  // back with the cookie. The desktop and Android apps, and a
                  // self-hosted origin, cannot hold that cookie: sending them
                  // to the portal's sign-in ends with a session in some
                  // browser and none here — which used to be this screen's
                  // only advice, with the button missing on top when the
                  // build knew no portal. They link this device instead, with
                  // a code approved wherever they are already signed in.
                  !canHoldProviderCookie(knownPortalUrl) ? (
                    <Column key='no-session-link' gap='0.75rem'>
                      <p key='copy'>
                        {`Your backup is kept by your ${PRODUCT_NAME} account. Connect this device to it to restore.`}
                      </p>
                      <LinkProviderPanel
                        key='link'
                        portalUrl={knownPortalUrl}
                        onLinked={() => setRestoreAttempt(n => n + 1)}
                      />
                    </Column>
                  ) : (
                    <Column key='no-session' gap='0.75rem'>
                      <p key='copy'>
                        {`To restore your account, sign in to your ${PRODUCT_NAME} account first, then come back here.`}
                      </p>
                      {knownPortalUrl && (
                        <Button
                          key='signin'
                          type='button'
                          onClick={() => {
                            // `/signin` rather than the root, which is the sales
                            // page — someone mid-recovery should land on the form.
                            window.location.assign(
                              new URL('/signin', knownPortalUrl).toString(),
                            );
                          }}
                        >
                          {`Sign in to your ${PRODUCT_NAME} account`}
                        </Button>
                      )}
                    </Column>
                  )
                ) : restore.phase === 'no-backup' ? (
                  <p key='no-backup'>
                    No recovery backup was found for {restore.email}. Account
                    recovery only works if you enabled it earlier.
                  </p>
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
                    verifySecret
                    stepIndicatorPortal={stepDotsSlotRef.current}
                    defaultProfileName={managedUsername}
                    offerRecoveryBackup={fromManaged}
                    onBackupWithPasskey={
                      fromManaged ? backupWithPasskey : undefined
                    }
                    onBackupWithCode={fromManaged ? backupWithCode : undefined}
                    onAfterCreate={
                      fromManaged ? enableEncryptedBackup : undefined
                    }
                    onDone={() => {
                      // After verify, NewIdentitySection navigates to privateDrive / home
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
                onClick={() => setStep('welcome')}
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

  @media (prefers-reduced-motion: reduce) {
    animation: none;
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
