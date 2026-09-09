import { useEffect, useState } from 'react';
import { styled } from 'styled-components';
import { FaKey } from 'react-icons/fa6';
import { Agent, useStore } from '@tomic/react';
import { Button } from './Button';
import { Column, Row } from './Row';
import { CodeBlock } from './CodeBlock';
import { SecretCodeBlock } from './SecretCodeBlock';
import { ErrorLook } from './ErrorLook';
import { InputStyled, InputWrapper } from './forms/InputStyles';
import { getManagedAccount, PRODUCT_NAME } from '../helpers/managed';
import { useSettings } from '../helpers/AppSettings';
import { fetchManagedInfo } from '../helpers/managedServer';
import { getManagedPortalUrl } from '../helpers/managed/cloudSync';
import {
  getRememberedManagedPortalUrl,
  safePortalUrl,
} from '../helpers/managed/api';
import {
  addRecoveryCodeWrapper,
  addPasskeyWrapper,
  buildEnvelopeV2,
  buildEnvelopeWithPasskeyAndCode,
  envelopeWrapperKinds,
  getRecoverySecret,
  isPasskeySupported,
  PrfUnsupportedError,
  readCachedBackups,
  revealSecretFromBackup,
  saveRecoverySecret,
  storeCachedRecoverySecret,
  type RecoverySecret,
} from '../helpers/managed/recovery';

type BackupState =
  | { phase: 'loading' }
  | { phase: 'none' }
  | {
      phase: 'ready';
      secret: RecoverySecret;
      /**
       * Whether the control plane is the one holding it. `false` means this
       * browser's cached copy is the only one, which a passkey still opens
       * here and an email cannot reach anywhere; `null` means we had no
       * session to ask with, so the question stays open rather than being
       * answered wrongly in either direction.
       */
      onServer: boolean | null;
    };

/**
 * Account recovery, for the managed (AtomicCloud) case: what currently
 * protects this account, plus the two actions that need the stored backup.
 *
 * Onboarding no longer displays the agent secret when a backup exists, so
 * this is where it lives. It's recoverable here because the backup blob holds
 * the secret encrypted under the DEK — the local keypair is non-extractable
 * (`agentStorage.ts`), but the blob is an independent copy, which is exactly
 * what it's for.
 */
export function AccountRecoveryCard({
  agentSubject,
}: {
  /** Picks this account's backup out of a device holding several. */
  agentSubject?: string;
}) {
  const [backup, setBackup] = useState<BackupState>({ phase: 'loading' });
  const [secret, setSecret] = useState<string | null>(null);
  const [newCode, setNewCode] = useState<string | null>(null);
  const [codeInput, setCodeInput] = useState('');
  const [needsCode, setNeedsCode] = useState(false);
  const [passkeyAdded, setPasskeyAdded] = useState(false);
  /**
   * The secret being enrolled, typed by the user.
   *
   * Asked for rather than read, and this is the one flow where that is not
   * laziness: `agentStorage.ts` keeps the keypair non-extractable, which is
   * what stops a script on this page from stealing the identity, and it stops
   * us reading it back just as effectively. Onboarding can seal a backup
   * without asking because it is holding the secret it just generated; every
   * moment after that, the only copy outside the browser's key store is the
   * one the user saved.
   */
  const [secretInput, setSecretInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | undefined>();

  // Adding a wrapper is a *write* to the control plane, so unlike revealing
  // the secret it can't work from the local cache alone. Known up front so
  // the UI can offer a way in rather than failing on click.
  const { baseURL, drive } = useSettings();
  const store = useStore();
  const [hasSession, setHasSession] = useState<boolean | null>(null);
  const [accountEmail, setAccountEmail] = useState<string | null>(null);
  const [portalUrl, setPortalUrl] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    void (async () => {
      const [session, info] = await Promise.all([
        getManagedAccount().catch(() => null),
        fetchManagedInfo(baseURL).catch(() => null),
      ]);

      if (cancelled) return;

      setHasSession(!!session);
      // Kept for the passkey's label, which is what the user will see in their
      // password manager a year from now when they have forgotten what this
      // credential was for.
      setAccountEmail(session?.email ?? null);
      // Resolve the portal the same way every other surface does, rather than
      // reading `info.portalUrl` straight off the connected node.
      //
      // That direct read meant only a *managed* node could produce a portal
      // link, so this card hid "Sign in to add a recovery code" on exactly the
      // devices that need it — a browser pointed at a self-hosted or local
      // node, or a desktop app on its own embedded one. Worse, the hint below
      // still told the reader to sign in, because it keys off `hasSession`
      // alone: instructions to do something with no way to do it.
      setPortalUrl(
        safePortalUrl(
          getManagedPortalUrl(info) ?? getRememberedManagedPortalUrl(),
        ) ?? null,
      );
    })();

    return () => {
      cancelled = true;
    };
  }, [baseURL]);

  useEffect(() => {
    // Wait for the session answer. Without it an empty server response is
    // ambiguous — no row stored, or nobody to ask — and this card would have
    // to guess which.
    if (hasSession === null) return;

    let cancelled = false;

    void (async () => {
      // Server copy when a session can reach it, otherwise this device's
      // cached one. Using the server alone was wrong: after signing in with
      // a passkey off the local cache there's no portal session, so a
      // perfectly good backup reported itself as "nothing protects this
      // account" — and refused to show a secret it could plainly decrypt.
      //
      // Which of the two answered is kept, though. Reporting them as one thing
      // is what let this card say "you can get back in with your passkey"
      // while the Sync page said no backup was stored: both were reading
      // honestly, from different places.
      let fromServer: RecoverySecret | null = null;
      let serverAnswered = false;

      if (hasSession) {
        try {
          fromServer = await getRecoverySecret();
          serverAnswered = true;
        } catch {
          // Control plane unreachable; the cache below is the fallback.
        }
      }

      if (cancelled) return;

      if (
        fromServer &&
        (!agentSubject || fromServer.agent_subject === agentSubject)
      ) {
        setBackup({ phase: 'ready', secret: fromServer, onServer: true });

        return;
      }

      const cached = readCachedBackups();
      const mine = agentSubject
        ? cached.find(entry => entry.agent_subject === agentSubject)
        : cached[cached.length - 1];

      setBackup(
        mine
          ? {
              phase: 'ready',
              secret: mine,
              onServer: serverAnswered ? false : null,
            }
          : { phase: 'none' },
      );
    })();

    return () => {
      cancelled = true;
    };
  }, [agentSubject, hasSession]);

  async function handleReveal() {
    if (needsCode && !codeInput.trim()) return;

    setLoading(true);
    setError(undefined);

    try {
      const revealed = await revealSecretFromBackup(
        codeInput.trim() || undefined,
        agentSubject,
      );

      if (revealed === null) {
        // Don't collapse the card to "nothing protects this account" — we
        // know a backup exists (it's what rendered these buttons). Say the
        // reveal failed and leave the other actions in place.
        setError('Could not reach your backup. Try again.');

        return;
      }

      setSecret(revealed);
      setCodeInput('');
      setNeedsCode(false);
    } catch (e) {
      const message =
        e instanceof Error ? e.message : 'Could not show your secret.';

      // The helper asks for a code when that's the only way in.
      if (
        message.toLowerCase().includes('enter your recovery') ||
        (backup.phase === 'ready' &&
          envelopeWrapperKinds(backup.secret).hasCode)
      ) {
        setNeedsCode(true);
      }

      setError(
        !needsCode &&
          backup.phase === 'ready' &&
          envelopeWrapperKinds(backup.secret).hasCode
          ? 'Could not unlock with a passkey. Use your recovery code instead.'
          : message,
      );
    } finally {
      setLoading(false);
    }
  }

  /**
   * Turn a typed agent secret into a stored backup.
   *
   * Deliberately the same shape onboarding uses: a passkey when the
   * authenticator can do PRF, a generated recovery code when it cannot, and
   * the code path as the landing spot when a passkey turns out mid-flight not
   * to support PRF. Two ways to enrol the same account would eventually be two
   * behaviours, and this is not a place to have a second opinion about how a
   * key is wrapped.
   */
  async function handleSetUp() {
    const typed = secretInput.trim();

    if (!typed) return;

    setLoading(true);
    setError(undefined);

    try {
      // The paste has to be checked against the identity this device already
      // holds, or a typo stores a backup that restores as somebody else. Public
      // keys rather than subjects: the same key can be written as a DID or as a
      // legacy `/agents/{pubkey}` URL, and a string compare would reject a
      // correct secret purely for being from the older era.
      const current = store.getAgent();
      const typedAgent = await Agent.fromSecret(typed).catch(() => null);

      if (!typedAgent) {
        setError('That does not look like an agent secret.');

        return;
      }

      if (current) {
        const [mine, theirs] = await Promise.all([
          current.getPublicKey(),
          typedAgent.getPublicKey(),
        ]);

        if (mine !== theirs) {
          setError(
            'That secret belongs to a different account than the one signed in here.',
          );

          return;
        }
      }

      // The secret's own subject, not this card's prop. `decodeSecret`
      // rewrites a pre-DID `https://server/agents/{pubkey}` to
      // `did:ad:agent:{pubkey}` on the way through, and the control plane
      // accepts nothing else — while the prop can still be the legacy URL,
      // because that is what finds the Agent resource holding the name and
      // drives. Sending the prop rejected exactly the accounts old enough to
      // have no backup yet.
      const subject = typedAgent.subject ?? agentSubject;

      if (!subject) {
        setError('That secret carries no account to back up.');

        return;
      }

      // Only a DID names a drive to the control plane, and the setting holds
      // whatever the drive is *addressed* by, which on an HTTP server is a
      // URL. Sending that was rejected outright; the field is optional, and a
      // backup with no drive named still restores the agent, which is the part
      // that cannot be regenerated.
      const driveSubject = drive?.startsWith('did:ad:') ? drive : null;

      let request;

      // Passkey plus code, as at onboarding: the passkey reaches only the
      // devices its vendor syncs it to, the code reaches the rest.
      if (await isPasskeySupported()) {
        try {
          const built = await buildEnvelopeWithPasskeyAndCode({
            secret: typed,
            agentSubject: subject,
            driveSubject,
            userName: accountEmail ?? 'Atomic account',
          });
          request = built.request;
          setNewCode(built.recoveryCode);
        } catch (e) {
          // Only knowable by trying, so this is a normal outcome rather than a
          // failure: fall through to the code path instead of dead-ending on
          // an authenticator that cannot wrap anything.
          if (!(e instanceof PrfUnsupportedError)) throw e;
        }
      }

      if (!request) {
        const built = await buildEnvelopeV2({
          secret: typed,
          agentSubject: subject,
          driveSubject,
        });
        request = built.request;
        setNewCode(built.recoveryCode);
      }

      const saved = await saveRecoverySecret(request);
      // Drop the secret the moment it is sealed. It stays in the DOM no longer
      // than it has to, and the card below is about the backup, not about what
      // was typed to make it.
      setSecretInput('');
      setBackup({ phase: 'ready', secret: saved, onServer: true });
    } catch (e) {
      setError(
        e instanceof Error ? e.message : 'Could not set up account recovery.',
      );
    } finally {
      setLoading(false);
    }
  }

  /** Put this device's sealed copy where an email can reach it. */
  async function handleStoreOnServer() {
    if (backup.phase !== 'ready') return;

    setLoading(true);
    setError(undefined);

    try {
      const saved = await storeCachedRecoverySecret(backup.secret);
      setBackup({ phase: 'ready', secret: saved, onServer: true });
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : `Could not store your backup with ${PRODUCT_NAME}.`,
      );
    } finally {
      setLoading(false);
    }
  }

  async function handleAddCode() {
    setLoading(true);
    setError(undefined);

    try {
      const { recoveryCode, saved } =
        await addRecoveryCodeWrapper(agentSubject);
      setNewCode(recoveryCode);
      setBackup({ phase: 'ready', secret: saved, onServer: true });
    } catch (e) {
      setError(
        e instanceof Error ? e.message : 'Could not add a recovery code.',
      );
    } finally {
      setLoading(false);
    }
  }

  async function handleAddPasskey() {
    if (!needsCode || !codeInput.trim()) {
      setNeedsCode(true);
      setError(undefined);

      return;
    }

    if (!agentSubject) return;

    setLoading(true);
    setError(undefined);
    setPasskeyAdded(false);

    try {
      const saved = await addPasskeyWrapper(
        codeInput.trim(),
        agentSubject,
        accountEmail ?? 'Atomic account',
      );
      setBackup({ phase: 'ready', secret: saved, onServer: true });
      setCodeInput('');
      setNeedsCode(false);
      setPasskeyAdded(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not add a passkey.');
    } finally {
      setLoading(false);
    }
  }

  if (backup.phase === 'loading') return null;

  if (backup.phase === 'none') {
    return (
      <Column gap='0.75rem'>
        <Protections>
          Nothing protects this account but the secret you saved during setup.
          Lose every device you are signed in on and that copy is all there is.
        </Protections>
        <p>
          You can store an encrypted backup now. Paste the secret and this
          device seals it before sending, so {PRODUCT_NAME} holds a blob it
          cannot read and your email plus a passkey or recovery code gets you
          back in on a new device.
        </p>
        <Hint>
          We have to ask you for it. This browser keeps your key where scripts
          cannot read it, which protects you and also means we cannot fetch the
          secret ourselves.
        </Hint>
        {hasSession === false && portalUrl ? (
          <Row>
            <Button
              subtle
              data-test='signin-to-set-up-recovery'
              onClick={() => window.open(`${portalUrl}/dashboard`, '_blank')}
            >
              Sign in to set up recovery
            </Button>
          </Row>
        ) : (
          <>
            <InputWrapper hasPrefix>
              <FaKey />
              <InputStyled
                value={secretInput}
                onChange={e => setSecretInput(e.target.value)}
                type='password'
                placeholder='Your agent secret'
                aria-label='Your agent secret'
              />
            </InputWrapper>
            <Row>
              <Button
                onClick={handleSetUp}
                disabled={loading || !secretInput.trim()}
                data-test='set-up-recovery'
              >
                {loading ? 'Setting up…' : 'Set up account recovery'}
              </Button>
            </Row>
          </>
        )}
        {hasSession === false && !portalUrl ? (
          <Hint>
            Storing a backup is a write to {PRODUCT_NAME}, so it needs you
            signed in there first.
          </Hint>
        ) : null}
        {error && <ErrorLook>{error}</ErrorLook>}
      </Column>
    );
  }

  const { hasPasskey, hasCode } = envelopeWrapperKinds(backup.secret);
  const deviceOnly = backup.onServer === false;

  return (
    <Column gap='0.75rem'>
      <Protections>
        {/* One expression, because JSX turns the newline between two of them
            into a space and the sentence read "your passkey ." */}
        You can get back in with:{' '}
        {`${
          [hasPasskey && 'your passkey', hasCode && 'your recovery code']
            .filter(Boolean)
            .join(' or ') || 'your recovery password'
        }${deviceOnly ? ', on this device' : ''}.`}
      </Protections>

      {/* The gap worth naming: everything above still works here, and none of
          it survives this browser. Said plainly because the Sync page reads
          the server copy, so a card that stayed quiet about which copy it
          found is how the two came to disagree. */}
      {deviceOnly ? (
        <Column gap='0.5rem'>
          <Hint>
            This backup is sealed in this browser only. {PRODUCT_NAME} is not
            holding a copy, so a new device could not get you back in.
          </Hint>
          <Row>
            <Button
              onClick={handleStoreOnServer}
              disabled={loading}
              data-test='store-backup-on-server'
            >
              {loading ? 'Storing…' : `Store it with ${PRODUCT_NAME}`}
            </Button>
          </Row>
        </Column>
      ) : null}

      {needsCode ? (
        <InputWrapper hasPrefix>
          <FaKey />
          <InputStyled
            value={codeInput}
            onChange={e => setCodeInput(e.target.value)}
            type='password'
            placeholder='Recovery code'
            aria-label='Recovery code'
          />
        </InputWrapper>
      ) : null}
      {hasCode ? (
        <Column gap='0.5rem'>
          <Row gap='1rem' wrapItems>
            <Button
              subtle
              disabled={loading}
              onClick={() => {
                setNeedsCode(true);
                setError(undefined);
              }}
            >
              Use recovery code
            </Button>
            {hasSession === true ? (
              <Button
                subtle
                disabled={loading || !agentSubject}
                onClick={handleAddPasskey}
                data-test='add-passkey'
              >
                Add a passkey
              </Button>
            ) : portalUrl ? (
              <Button
                subtle
                onClick={() => window.open(`${portalUrl}/dashboard`, '_blank')}
              >
                Sign in to add a passkey
              </Button>
            ) : null}
          </Row>
          {needsCode ? (
            <Hint>
              Enter your recovery code to show your secret or add a passkey on
              this device. Your existing recovery code will keep working.
            </Hint>
          ) : null}
          {passkeyAdded ? (
            <p>Passkey added. Your recovery code still works.</p>
          ) : null}
        </Column>
      ) : null}

      {secret ? (
        <Column gap='0.5rem'>
          <p>
            This <strong>is</strong> your account — anyone holding it is you, on
            any device, forever. It can&apos;t be changed or revoked, and
            it&apos;s the only thing that still works if {PRODUCT_NAME}{' '}
            disappears. Store it like a passport, not a password.
          </p>
          <SecretCodeBlock className='revealed-agent-secret' content={secret} />
          <Row>
            <Button subtle onClick={() => setSecret(null)}>
              Hide
            </Button>
          </Row>
        </Column>
      ) : (
        <Column gap='0.5rem'>
          <Row gap='1rem' wrapItems>
            <Button
              subtle
              onClick={handleReveal}
              disabled={loading || (needsCode && !codeInput.trim())}
              data-test='reveal-secret'
            >
              {loading ? 'Unlocking…' : 'Show my agent secret'}
            </Button>
            {hasPasskey && !hasCode && hasSession !== false ? (
              <Button
                subtle
                onClick={handleAddCode}
                disabled={loading}
                data-test='add-recovery-code'
              >
                Add a recovery code
              </Button>
            ) : null}
            {hasPasskey && !hasCode && hasSession === false && portalUrl ? (
              <Button
                subtle
                data-test='signin-to-add-code'
                onClick={() => window.open(`${portalUrl}/dashboard`, '_blank')}
              >
                Sign in to add a recovery code
              </Button>
            ) : null}
          </Row>
          {hasPasskey && !hasCode ? (
            <Hint>
              A recovery code is a spare key for when your passkey isn&apos;t
              available. You&apos;ll need your email to use it, so it&apos;s
              safe to keep on paper.
              {hasSession === false
                ? ` Creating one changes your stored backup, so it needs you signed in to ${PRODUCT_NAME} — your passkey alone can read the backup, but not change it.`
                : ''}
            </Hint>
          ) : null}
        </Column>
      )}

      {newCode ? (
        <Column gap='0.5rem'>
          <p>
            <strong>Save this recovery code.</strong> It gets you back in on a
            new device, and you will need your email with it. We cannot show it
            again, but you can generate a new one here any time, which retires
            this one.
          </p>
          <CodeBlock
            className='recovery-code-block'
            wordWrap
            content={newCode}
          />
        </Column>
      ) : null}

      {error && <ErrorLook>{error}</ErrorLook>}
    </Column>
  );
}

const Protections = styled.p`
  margin: 0;
  color: ${p => p.theme.colors.textLight};
`;

const Hint = styled.p`
  margin: 0;
  font-size: 0.9rem;
  color: ${p => p.theme.colors.textLight};
`;
