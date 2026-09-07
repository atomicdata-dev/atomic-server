import React, { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Agent, JSCryptoProvider, core, useStore } from '@tomic/react';
import { fetchPrivateDriveSubject } from '../helpers/privateDrive';
import { isOriginWithoutNode } from '../helpers/originNode';
import { useSettings } from '../helpers/AppSettings';
import { saveAgentToIDB } from '../helpers/agentStorage';
import { reopenRestoredDrive } from '../helpers/driveData';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { constructOpenURL } from '../helpers/navigation';
import { Button } from './Button';
import { Column, Row } from './Row';
import { CodeBlock } from './CodeBlock';
import { SecretCodeBlock } from './SecretCodeBlock';
import toast from 'react-hot-toast';
import { FaDownload } from 'react-icons/fa6';
import { styled } from 'styled-components';
import { InputStyled, InputWrapper } from './forms/InputStyles';
import Field from './forms/Field';
import { PRODUCT_NAME } from '../helpers/managed';
import {
  isPasskeySupported,
  PrfUnsupportedError,
} from '../helpers/managed/recovery';

type Step =
  | 'idle'
  | 'creating'
  | 'profile'
  | 'creating-drive'
  | 'recovery-backup'
  | 'secret'
  | 'verify';

interface NewIdentitySectionProps {
  /** Called after the drive is created (or skipped). */
  onDone: () => void;
  /** Called after the agent and drive are created. Use this for any extra server-side steps (e.g. /setup). */
  onAfterCreate?: (driveSubject: string) => Promise<void>;
  /** If true, start creation immediately on mount without showing the button. */
  autoStart?: boolean;
  /**
   * If true, after confirming the secret is saved, the user is signed out and
   * must re-enter the secret to verify they saved it.
   */
  verifySecret?: boolean;
  /** Optional portal target for the step dots indicator. */
  stepIndicatorPortal?: Element | null;
  /** Prefill the profile-name field (e.g. from a managed account email). */
  defaultProfileName?: string;
  /**
   * If true, after creating the identity, offer to back up the agent secret
   * (envelope-encrypted, client-side) so the account can be restored. Only
   * makes sense when signed in to a managed account that can store it.
   */
  offerRecoveryBackup?: boolean;
  /** Encrypt + store the secret under a newly registered passkey AND a
   * freshly generated recovery code. Resolves with the plaintext code to
   * show the user once: the passkey only reaches the devices its vendor
   * syncs it to, the code reaches the rest. Rejects with
   * `PrfUnsupportedError` if this device can't do PRF, which moves the step
   * onto the code-only path. */
  onBackupWithPasskey?: (secret: string) => Promise<string>;
  /** Encrypt + store the secret under a freshly generated recovery code.
   * Resolves with the plaintext code to show the user once. The fallback for
   * devices without passkey support, or when the user asks for it. */
  onBackupWithCode?: (secret: string) => Promise<string>;
}

interface IdentityData {
  secret: string;
  agentSubject: string;
  privateKey: string;
  profileName: string;
  /** The personal drive created for this identity, so onboarding can open it
   * directly when the secret/verify steps are skipped. */
  driveSubject?: string;
}

/**
 * Multi-step onboarding flow for creating a new identity.
 * Steps: idle → creating → profile → creating-drive → secret → verify → done
 *
 * After the username step we create one private drive (read/write: agent only) and set it as home.
 */
export function NewIdentitySection({
  onDone,
  onAfterCreate,
  autoStart = false,
  verifySecret = false,
  stepIndicatorPortal,
  defaultProfileName,
  offerRecoveryBackup = false,
  onBackupWithPasskey,
  onBackupWithCode,
}: NewIdentitySectionProps) {
  const store = useStore();
  const { setAgent, setDrive } = useSettings();
  const navigate = useNavigateWithTransition();
  const [step, setStep] = useState<Step>('idle');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const [identity, setIdentity] = useState<IdentityData | null>(null);
  const creatingIdentity = useRef(false);
  /** True after the user copies the secret or saves the backup file. */
  const [secretBackedUp, setSecretBackedUp] = useState(false);
  /** Set once a backup resolves; shown once, then never again. */
  const [recoveryCode, setRecoveryCode] = useState<string | null>(null);
  /** The backup also has a passkey wrapper, so the code screen can say what
   * each key is for. */
  const [passkeyRegistered, setPasskeyRegistered] = useState(false);
  /** null while the capability probe is still running. */
  const [passkeySupported, setPasskeySupported] = useState<boolean | null>(
    null,
  );
  /** True once we've committed to the recovery-code path — either because
   * this device can't do passkeys, or the user asked for a code instead. */
  const [useCodeFallback, setUseCodeFallback] = useState(false);

  useEffect(() => {
    if (autoStart) {
      handleCreate();
    }
  }, []);

  // ─── Step: Create Identity ───────────────────────────────────────────────

  async function handleCreate() {
    // React StrictMode replays mount effects. A second key generation would
    // replace the active agent while the first identity is still onboarding.
    if (creatingIdentity.current) return;
    creatingIdentity.current = true;
    setStep('creating');
    setLoading(true);
    setError(undefined);

    try {
      const agentKeys = await Agent.generateKeyPair();
      const agentDID = `did:ad:agent:${agentKeys.publicKey}`;
      const agentProvider = new JSCryptoProvider(agentKeys.privateKey);
      const newAgent = new Agent(agentProvider, agentDID);

      store.setAgent(newAgent);

      // With no node behind the app's origin (the hosted build on the free
      // tier — see `originNode.ts`) this identity exists nowhere but here.
      // Its own resource, and the drive made below, must route to local
      // storage from their first save, or every commit parks in the outbox
      // waiting for a server that is not coming. Same registration the demo
      // guest uses; `enableCloudSyncForDrive` lifts it when a node is
      // assigned. Registered right after `setAgent` and before anything
      // async, so no consumer can mount `useResource(agent)` and fetch first.
      if (isOriginWithoutNode(store.getServerUrl())) {
        store.registerLocalOnlyDrive(agentDID);
        store.registerLocalOnlyDrive(await newAgent.privateDriveSubject());
      }

      setIdentity({
        secret: '', // will be built after drive is created
        agentSubject: agentDID,
        privateKey: agentKeys.privateKey,
        profileName: '',
      });

      setStep('profile');
    } catch (e) {
      creatingIdentity.current = false;
      setError(e instanceof Error ? e.message : String(e));
      setStep('idle');
    } finally {
      setLoading(false);
    }
  }

  // ─── Step: Profile → private drive (automatic) ───────────────────────────

  function handleProfileSave(name: string) {
    const trimmed = name.trim();
    setIdentity(prev => (prev ? { ...prev, profileName: trimmed } : null));
    void createPrivateDrive(trimmed);
  }

  /** One private drive per user on this server; becomes default home / initialDrive. */
  async function createPrivateDrive(username: string) {
    if (!identity) return;

    setStep('creating-drive');
    setLoading(true);
    setError(undefined);

    try {
      const agent = store.getAgent();

      if (!agent || agent.subject === undefined) {
        throw new Error('No agent set');
      }

      // Set the display name on the agent resource
      const agentResource = store.getResourceLoading(identity.agentSubject, {
        newResource: true,
      });
      const publicKey = identity.agentSubject.replace('did:ad:agent:', '');

      await agentResource.set(core.properties.publicKey, publicKey);
      await agentResource.set(core.properties.isA, [core.classes.agent]);

      if (username) {
        await agentResource.set(core.properties.name, username);
      }

      await agentResource.save();

      const driveName = username ? `${username}'s Drive` : 'Personal';

      const resource = await store.createDrive(driveName, {
        description:
          'Your private space on this server. Only you can read and write here.',
      });

      const finalSecret = Agent.buildSecret(
        identity.privateKey,
        identity.agentSubject,
        resource.subject,
      );

      await saveAgentToIDB(finalSecret);

      setIdentity(prev =>
        prev
          ? { ...prev, secret: finalSecret, driveSubject: resource.subject }
          : null,
      );

      const updatedAgent = await Agent.fromSecret(finalSecret);
      store.setAgent(updatedAgent);

      setDrive(resource.subject);

      if (onAfterCreate) {
        await onAfterCreate(resource.subject);
      }

      setStep(
        offerRecoveryBackup && (onBackupWithPasskey || onBackupWithCode)
          ? 'recovery-backup'
          : 'secret',
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setStep('profile');
    } finally {
      setLoading(false);
    }
  }

  // ─── Step: Back up secret (encrypted recovery) ───────────────────────────

  // Probed once the backup step is reached, so the step can lead with the
  // passkey path (passkey + code) and only fall back to a code alone where
  // PRF genuinely isn't available.
  useEffect(() => {
    if (step !== 'recovery-backup') return;
    let cancelled = false;

    void isPasskeySupported().then(supported => {
      if (cancelled) return;

      setPasskeySupported(supported);

      if (!supported) setUseCodeFallback(true);
    });

    return () => {
      cancelled = true;
    };
  }, [step]);

  /**
   * End onboarding without ever showing the raw secret.
   *
   * Only safe once a backup exists: the secret is then recoverable at any
   * time from Settings (one passkey prompt), so displaying it here would just
   * be a second thing to store. With no backup, the reveal + verify steps
   * stay — it really is the only copy.
   */
  async function finishWithoutSecretStep() {
    if (identity?.driveSubject) {
      setDrive(identity.driveSubject);
      // An earlier lookup can have cached "not found" before creation.
      // Read the now-persisted drive and profile before opening the workspace.
      await reopenRestoredDrive(store, identity.driveSubject);
      navigate(constructOpenURL(identity.driveSubject));
    }

    onDone();
  }

  async function handleBackupWithPasskey() {
    if (!identity || !onBackupWithPasskey) {
      setStep('secret');

      return;
    }

    setLoading(true);
    setError(undefined);

    try {
      const code = await onBackupWithPasskey(identity.secret);
      setPasskeyRegistered(true);
      setRecoveryCode(code);
    } catch (e) {
      if (e instanceof PrfUnsupportedError) {
        // The authenticator turned out not to support PRF (only knowable by
        // trying). Move to the code path rather than dead-ending.
        setPasskeySupported(false);
        setUseCodeFallback(true);
        setError(`${e.message} You can save a recovery code instead.`);
      } else {
        setError(
          e instanceof Error
            ? e.message
            : 'Could not back up your secret. You can still save it yourself.',
        );
      }
    } finally {
      setLoading(false);
    }
  }

  async function handleGenerateRecoveryCode() {
    if (!identity || !onBackupWithCode) {
      setStep('secret');

      return;
    }

    setLoading(true);
    setError(undefined);

    try {
      const code = await onBackupWithCode(identity.secret);
      setRecoveryCode(code);
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : 'Could not back up your secret. You can still save it yourself.',
      );
    } finally {
      setLoading(false);
    }
  }

  // ─── Step: Confirm Secret ───────────────────────────────────────────────

  function handleConfirmSecret() {
    if (!identity) return;

    if (verifySecret) {
      // Sign out and go to verify step
      setAgent(undefined);
      saveAgentToIDB(undefined);
      setStep('verify');
    } else {
      // Skip verify, we're done
      onDone();
    }
  }

  // ─── Step: Verify Secret ──────────────────────────────────────────────────

  async function handleVerify(trimmedInput: string) {
    if (!trimmedInput || !identity) return;

    setLoading(true);
    setError(undefined);

    try {
      const agent = await Agent.fromSecret(trimmedInput);
      await saveAgentToIDB(trimmedInput);
      setAgent(agent);

      const home = await fetchPrivateDriveSubject(store, agent);

      if (home) {
        setDrive(home);
        navigate(constructOpenURL(home));
      }

      onDone();
    } catch (e) {
      console.error('Failed to verify secret:', e);
      setError('The secret is invalid. Make sure you copied it correctly.');
    } finally {
      setLoading(false);
    }
  }

  // ─── Render ────────────────────────────────────────────────────────────────

  const stepIndicator = (
    <StepIndicator step={step} verifySecret={verifySecret} />
  );

  return (
    <Column gap='1.5rem'>
      {stepIndicatorPortal
        ? createPortal(stepIndicator, stepIndicatorPortal, 'step-indicator')
        : stepIndicator}

      {step === 'idle' && (
        <Column key='idle' gap='1rem'>
          <p key='copy'>
            Create a new Agent on this server. We will set your username and
            create a private drive as your home.
          </p>
          {error && <ErrorText key='error'>{error}</ErrorText>}
          <Button key='create' onClick={handleCreate} disabled={loading}>
            {loading ? 'Generating...' : 'Create new identity'}
          </Button>
        </Column>
      )}

      {step === 'creating' && (
        <Column key='creating' gap='1rem'>
          <p>Generating your identity...</p>
        </Column>
      )}

      {step === 'profile' && identity && (
        <ProfileStep
          key='profile'
          error={error}
          loading={loading}
          onSave={handleProfileSave}
          defaultName={defaultProfileName}
        />
      )}

      {step === 'creating-drive' && (
        <Column key='creating-drive' gap='1rem'>
          <p>Creating your private drive…</p>
        </Column>
      )}

      {step === 'recovery-backup' && identity && (
        <RecoveryBackupStep
          key='recovery-backup'
          error={error}
          loading={loading}
          passkeySupported={passkeySupported}
          useCodeFallback={useCodeFallback || !onBackupWithPasskey}
          recoveryCode={recoveryCode}
          passkeyRegistered={passkeyRegistered}
          onUsePasskey={handleBackupWithPasskey}
          onUseCodeInstead={() => {
            setError(undefined);
            setUseCodeFallback(true);
          }}
          onGenerate={handleGenerateRecoveryCode}
          onContinue={finishWithoutSecretStep}
          onSkip={() => {
            setError(undefined);
            setStep('secret');
          }}
        />
      )}

      {step === 'secret' && identity && (
        <SecretStep
          key='secret'
          secret={identity.secret}
          secretBackedUp={secretBackedUp}
          onCopy={() => setSecretBackedUp(true)}
          onDownloadBackup={() => setSecretBackedUp(true)}
          onConfirm={handleConfirmSecret}
          verifySecret={verifySecret}
        />
      )}

      {step === 'verify' && identity && (
        <VerifyStep
          key='verify'
          secret={identity.secret}
          onVerify={handleVerify}
        />
      )}
    </Column>
  );
}

// ─── Sub-components ─────────────────────────────────────────────────────────

const STEPS_SECRET = ['profile', 'secret', 'verify'];
const STEPS_NO_SECRET = ['profile', 'secret'];

function StepIndicator({
  step,
  verifySecret,
}: {
  step: Step;
  verifySecret: boolean;
}) {
  const steps = verifySecret ? STEPS_SECRET : STEPS_NO_SECRET;
  const currentIndex = steps.indexOf(step);

  if (
    currentIndex === -1 ||
    step === 'idle' ||
    step === 'creating' ||
    step === 'creating-drive'
  ) {
    return null;
  }

  return (
    <StepDots>
      {steps.map((s, i) => (
        <StepDot key={s} active={i === currentIndex} done={i < currentIndex} />
      ))}
    </StepDots>
  );
}

function StepDot({ active, done }: { active: boolean; done: boolean }) {
  return (
    <Dot
      style={{
        background: active ? '#333' : done ? '#888' : '#ccc',
      }}
    />
  );
}

const Dot = styled.span`
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
`;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const StepDots = styled.div.attrs(() => ({ 'data-step-dots': 'true' }) as any)`
  display: flex;
  gap: 6px;
  justify-content: center;
`;

function downloadSecretBackupFile(secret: string): void {
  const when = new Date().toISOString();
  const lines = [
    'Atomic Server — agent secret backup',
    '',
    'IMPORTANT: Store this file (or the secret line) somewhere only you can access.',
    'Without it you cannot sign in after clearing the browser or on another device.',
    'Anyone who gets this secret can access your account on this server.',
    '',
    `Created: ${when}`,
    '',
    '--- SECRET (single line; keep exactly as-is) ---',
    secret,
    '--- END ---',
    '',
  ];
  const blob = new Blob([lines.join('\n')], {
    type: 'text/plain;charset=utf-8',
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `atomic-agent-backup-${when.slice(0, 10)}.txt`;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function SecretStep({
  secret,
  secretBackedUp,
  onCopy,
  onDownloadBackup,
  onConfirm,
  verifySecret,
}: {
  secret: string;
  secretBackedUp: boolean;
  onCopy: () => void;
  onDownloadBackup: () => void;
  onConfirm: () => void;
  verifySecret: boolean;
}) {
  function handleDownload() {
    downloadSecretBackupFile(secret);
    toast.success(
      'Backup file downloaded — move it out of Downloads if you share this computer',
    );
    onDownloadBackup();
  }

  return (
    <Column gap='1rem'>
      <h3 key='title'>This is your account</h3>
      <p key='important'>
        Anyone who has this <strong>is</strong> you — on any device, forever. It
        can&apos;t be changed or revoked. It&apos;s also the only thing that
        still works if {PRODUCT_NAME} disappears.
      </p>
      <p key='ways'>
        Store it like a passport, not a password: a password manager, or{' '}
        <strong>Save backup file</strong> below and move it somewhere private.
        Never email or chat it.
      </p>
      <SecretCodeBlock
        key='code'
        className='secret-protected'
        content={secret}
        onCopy={onCopy}
      />
      <Row key='download' gap='0.75rem' wrapItems>
        <Button type='button' subtle onClick={handleDownload}>
          <FaDownload
            key='icon'
            aria-hidden
            style={{ marginRight: '0.45em' }}
          />
          Save backup file…
        </Button>
      </Row>
      {secretBackedUp ? (
        <React.Fragment key='confirm'>
          <p key='warning'>
            Are you sure you&apos;ve stored this secret somewhere safe? You
            cannot recover it if you lose it.
          </p>
          <Row key='confirm-row' gap='1rem' wrapItems>
            <Button onClick={onConfirm}>
              {verifySecret
                ? "Yes, I've stored it — sign me out to verify"
                : "Yes, I've stored it safely"}
            </Button>
          </Row>
        </React.Fragment>
      ) : (
        <Button key='disabled' disabled>
          Copy the secret or save the backup file to continue
        </Button>
      )}
    </Column>
  );
}

function VerifyStep({
  secret,
  onVerify,
}: {
  secret: string;
  onVerify: (input: string) => void;
}) {
  const [input, setInput] = useState('');

  return (
    <Column gap='1rem'>
      <h3 key='title'>Verify your secret</h3>
      <p key='copy'>
        You have been signed out to verify that you saved your secret. Enter it
        below to sign in.
      </p>
      <Field key='field' label='Enter your Agent Secret' fieldId='agent-secret'>
        <InputWrapper>
          <InputStyled
            id='agent-secret'
            value={input}
            onChange={e => {
              const val = e.target.value;
              setInput(val);

              if (val.trim() === secret) {
                onVerify(val.trim());
              }
            }}
            type='password'
            placeholder='Paste your secret here'
            autoComplete='off'
            spellCheck='false'
            autoFocus
          />
        </InputWrapper>
      </Field>
    </Column>
  );
}

function ProfileStep({
  error,
  loading,
  onSave,
  defaultName,
}: {
  error: string | undefined;
  loading: boolean;
  onSave: (name: string) => void;
  defaultName?: string;
}) {
  const [name, setName] = useState(defaultName ?? '');

  function handleSave(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;

    onSave(name.trim());
  }

  return (
    <Column gap='1rem'>
      <h3 key='title'>Set your profile name!</h3>
      <p key='copy'>Others can read this. You can change this later.</p>
      <form key='form' onSubmit={handleSave}>
        <Column gap='1rem'>
          <Field
            key='field'
            label='Profile Name'
            fieldId='profile-name'
            error={error ? new Error(error) : undefined}
          >
            <InputWrapper>
              <InputStyled
                id='profile-name'
                value={name}
                onChange={e => setName(e.target.value)}
                type='text'
                placeholder='Enter your name'
                autoComplete='off'
                autoFocus
                disabled={loading}
              />
            </InputWrapper>
          </Field>
          <Row key='submit' gap='1rem' wrapItems>
            <ContinueButton type='submit' disabled={loading || !name.trim()}>
              {loading ? 'Creating drive…' : 'Save & continue'}
            </ContinueButton>
          </Row>
        </Column>
      </form>
    </Column>
  );
}

function RecoveryBackupStep({
  error,
  loading,
  passkeySupported,
  useCodeFallback,
  recoveryCode,
  passkeyRegistered,
  onUsePasskey,
  onUseCodeInstead,
  onGenerate,
  onContinue,
  onSkip,
}: {
  error: string | undefined;
  loading: boolean;
  passkeySupported: boolean | null;
  useCodeFallback: boolean;
  recoveryCode: string | null;
  passkeyRegistered: boolean;
  onUsePasskey: () => void;
  onUseCodeInstead: () => void;
  onGenerate: () => void;
  onContinue: () => void;
  onSkip: () => void;
}) {
  // Skipping is the one irreversible choice here: without a backup, a lost
  // secret means the account (and its data) can never be recovered — by anyone.
  // So skip is two-stage: the button arms a stark confirmation before it takes.
  const [confirmingSkip, setConfirmingSkip] = useState(false);
  /** True after the user copies the recovery code — same "confirm you saved
   * it before continuing" idiom as {@link SecretStep}'s `secretBackedUp`. */
  const [codeSaved, setCodeSaved] = useState(false);
  // A script-scope string rather than JSX text: as JSX text inside this
  // ternary, the i18n extractor (wuchale) emitted the nested-message form
  // without its enclosing callback, and the dev build threw
  // `_w_ctx_ is not defined` on every onboarding run. See the CI note in
  // atomic-saas's portal e2e.
  const confirmSavedLabel = "Yes, I've stored it safely";

  if (confirmingSkip) {
    return (
      <Column gap='1rem'>
        <h3 key='title'>Skip this?</h3>
        <SkipWarning key='warning' role='alert'>
          <strong>Then it&apos;s all on you.</strong> We&apos;ll show you your
          secret next — it&apos;s the only copy that will ever exist, nobody can
          reset it for you, and losing it means losing your account and
          everything in it. Fine if you&apos;ll genuinely keep it safe.
        </SkipWarning>
        <Row key='actions' gap='1rem' wrapItems>
          <ContinueButton
            type='button'
            onClick={() => setConfirmingSkip(false)}
            disabled={loading}
          >
            Protect my account
          </ContinueButton>
          <Button type='button' subtle onClick={onSkip} disabled={loading}>
            Skip anyway
          </Button>
        </Row>
      </Column>
    );
  }

  if (recoveryCode) {
    return (
      <Column gap='1rem'>
        <h3 key='title'>Save your recovery code</h3>
        {passkeyRegistered && (
          <p key='why'>
            Your passkey opens this account on this device and wherever it syncs
            to. This code opens it on every other device — a phone, a different
            browser, a new computer.
          </p>
        )}
        <p key='important'>
          Keep it somewhere safe. You&apos;ll need it — plus your email — to get
          back in. We can&apos;t show it again, but you can generate a new one
          from Settings whenever you like.
        </p>
        <StyledCodeBlock
          key='code'
          className='recovery-code-block'
          wordWrap
          content={recoveryCode}
          onCopy={() => setCodeSaved(true)}
        />
        {codeSaved ? (
          <React.Fragment key='confirm'>
            <p key='warning'>
              Are you sure you&apos;ve stored this code somewhere safe? You
              cannot recover your account without it.
            </p>
            <Row key='confirm-row' gap='1rem' wrapItems>
              <ContinueButton onClick={onContinue}>
                {confirmSavedLabel}
              </ContinueButton>
            </Row>
          </React.Fragment>
        ) : (
          <Button key='disabled' disabled>
            Copy the code to continue
          </Button>
        )}
      </Column>
    );
  }

  // Still probing what this device supports — don't flash the code path
  // first only to replace it a moment later.
  if (passkeySupported === null && !useCodeFallback) {
    return (
      <Column gap='1rem'>
        <h3 key='title'>Back up your secret?</h3>
        <p key='checking'>Checking what this device supports…</p>
      </Column>
    );
  }

  if (useCodeFallback) {
    return (
      <Column gap='1rem'>
        <h3 key='title'>Save a recovery code</h3>
        <p key='copy'>
          {passkeySupported === false
            ? 'This device can’t use passkeys, so we’ll give you a recovery code instead — a spare key for your account.'
            : 'A spare key for your account.'}{' '}
          You&apos;ll also need to sign in to your email to use it, so it&apos;s
          safe to keep in a password manager or on paper.
        </p>
        {error && <ErrorText key='error'>{error}</ErrorText>}
        <Row key='actions' gap='1rem' wrapItems>
          <ContinueButton type='button' onClick={onGenerate} disabled={loading}>
            {loading ? 'Generating…' : 'Generate my recovery code'}
          </ContinueButton>
          <Button
            type='button'
            subtle
            onClick={() => setConfirmingSkip(true)}
            disabled={loading}
          >
            Skip, I&apos;ll save it myself
          </Button>
        </Row>
      </Column>
    );
  }

  // The default path: a passkey for everyday unlocking, plus a recovery code
  // for the devices the passkey does not reach. Passkeys sync within one
  // vendor's keychain only, so "it works on your other devices" was true for
  // some of them; the code is what makes it true for all.
  return (
    <Column gap='1rem'>
      <h3 key='title'>Protect your account</h3>
      <p key='copy'>
        Use your fingerprint, face, or screen lock — the same one that unlocks
        this device. You&apos;ll also get a recovery code for devices your
        passkey doesn&apos;t sync to.
      </p>
      {error && <ErrorText key='error'>{error}</ErrorText>}
      <Row key='actions' gap='1rem' wrapItems>
        <ContinueButton type='button' onClick={onUsePasskey} disabled={loading}>
          {loading ? 'Waiting for your passkey…' : 'Use a passkey'}
        </ContinueButton>
        <Button
          type='button'
          subtle
          onClick={onUseCodeInstead}
          disabled={loading}
        >
          Use a recovery code instead
        </Button>
        <Button
          type='button'
          subtle
          onClick={() => setConfirmingSkip(true)}
          disabled={loading}
        >
          Skip, I&apos;ll save it myself
        </Button>
      </Row>
    </Column>
  );
}

// ─── Styles ──────────────────────────────────────────────────────────────────

const SkipWarning = styled.p`
  margin: 0;
  padding: 0.9rem 1rem;
  border-radius: ${p => p.theme.radius};
  border: 1px solid ${p => p.theme.colors.alert};
  background: ${p => p.theme.colors.alert}14;
  color: ${p => p.theme.colors.text};
  line-height: 1.5;

  strong {
    color: ${p => p.theme.colors.alert};
  }
`;

/**
 * The recovery code is deliberately *not* blurred: it's shown exactly once,
 * for the user to copy or write down there and then. The agent secret is the
 * opposite case and uses {@link SecretCodeBlock}.
 */
const StyledCodeBlock = styled(CodeBlock)`
  word-break: break-word;

  & button {
    top: ${p => p.theme.size(1)};
    right: ${p => p.theme.size(1)};
  }
`;

const ErrorText = styled.p`
  color: ${p => p.theme.colors.alert};
  margin: 0;
`;

const ContinueButton = styled(Button)`
  align-self: flex-start;
  padding-inline: 1rem;
`;
