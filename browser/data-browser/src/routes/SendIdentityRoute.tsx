import { useEffect, useState, type FormEvent } from 'react';
import { createRoute } from '@tanstack/react-router';
import { Button } from '../components/Button';
import { Column } from '../components/Row';
import { InputStyled, InputWrapper } from '../components/forms/InputStyles';
import {
  accountAddress,
  getManagedAccount,
  type ManagedAccount,
} from '../helpers/managed/session';
import { safePortalUrl } from '../helpers/managed/api';
import { getManagedPortalUrl } from '../helpers/managed/cloudSync';
import {
  canHoldProviderCookie,
  getRememberedProvider,
} from '../helpers/managed/deviceLink';
import { getUnlockableRecoverySecret } from '../helpers/managed/recovery';
import type { RecoverySecret } from '../helpers/managed/recovery';
import {
  describeLink,
  sendIdentity,
  unlockBackup,
  unlockMethods,
  type LinkDescription,
  type UnlockMethod,
} from '../helpers/managed/sendIdentity';
import { fetchManagedInfo } from '../helpers/managedServer';
import { useSettings } from '../helpers/AppSettings';
import {
  AccountSignInPanel,
  AccountSignInViaBrowser,
} from '../views/getting-started/AccountSignInPanel';
import {
  CardError,
  CardSubtitle,
  CardTitle,
  CtaButton,
  OnboardingCard,
  OnboardingWrap,
  Shell,
} from '../views/getting-started/chrome';
import { pathNames } from './paths';
import { appRoute } from './RootRoutes';

export const SendIdentityRoute = createRoute({
  path: pathNames.sendIdentity,
  component: () => <SendIdentityPage />,
  getParentRoute: () => appRoute,
  validateSearch: (search): { code: string } => ({
    code: typeof search.code === 'string' ? search.code.trim() : '',
  }),
});

type Phase =
  | { name: 'loading' }
  | { name: 'sign-in' }
  | { name: 'confirm'; link: LinkDescription; account: ManagedAccount }
  | {
      name: 'unlock';
      link: LinkDescription;
      recovery: RecoverySecret;
      methods: UnlockMethod[];
    }
  | { name: 'sending' }
  | { name: 'done' }
  | { name: 'failed'; message: string };

/**
 * /app/send-identity?code=<user code>
 *
 * Where a person lets an app they started on another device (the Atomic mobile
 * app) receive their identity. The app waits with a code and a key it made;
 * this page unlocks the account's backup here and seals the secret to that key,
 * so the provider only relays ciphertext. Nothing is sent without a press.
 */
function SendIdentityPage() {
  const { code } = SendIdentityRoute.useSearch();
  const { baseURL } = useSettings();
  const [phase, setPhase] = useState<Phase>({ name: 'loading' });
  const [attempt, setAttempt] = useState(0);
  const [portalUrl, setPortalUrl] = useState<string | null>(
    () =>
      safePortalUrl(getManagedPortalUrl() ?? getRememberedProvider()) ?? null,
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [codeInput, setCodeInput] = useState('');

  useEffect(() => {
    let cancelled = false;
    void fetchManagedInfo(baseURL).then(info => {
      if (!cancelled) {
        setPortalUrl(
          safePortalUrl(getManagedPortalUrl(info) ?? getRememberedProvider()) ??
            null,
        );
      }
    });

    return () => {
      cancelled = true;
    };
  }, [baseURL]);

  useEffect(() => {
    let cancelled = false;
    const fail = (message: string) =>
      !cancelled && setPhase({ name: 'failed', message });

    if (!code) {
      fail('This link has no code. Start again from your device.');

      return;
    }

    void (async () => {
      const account = await getManagedAccount().catch(() => null);

      if (cancelled) return;

      if (!account) {
        setPhase({ name: 'sign-in' });

        return;
      }

      try {
        const link = await describeLink(code);

        if (!link.appKey) {
          fail('That device did not ask for your identity.');
        } else if (link.alreadyApproved) {
          fail('This code was already used. Ask the device for a new one.');
        } else if (!cancelled) {
          setPhase({ name: 'confirm', link, account });
        }
      } catch (err) {
        fail(
          err instanceof Error ? err.message : 'Could not look up that code.',
        );
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [code, attempt]);

  /**
   * Unlock, then seal and deposit. False when the unlock failed (the caller
   * decides whether to say so); a failed deposit ends the page instead, since
   * the person cannot fix it from here.
   */
  async function finish(
    link: LinkDescription,
    recovery: RecoverySecret,
    method: UnlockMethod,
    input?: string,
    quiet = false,
  ): Promise<boolean> {
    let secret: string;

    try {
      secret = await unlockBackup(recovery, method, input);
    } catch (err) {
      if (!quiet) {
        setError(
          err instanceof Error ? err.message : 'Could not unlock your backup.',
        );
      }

      return false;
    }

    setPhase({ name: 'sending' });

    try {
      await sendIdentity(code, link, recovery, secret);
      setPhase({ name: 'done' });
    } catch (err) {
      setPhase({
        name: 'failed',
        message:
          err instanceof Error ? err.message : 'Could not send your identity.',
      });
    }

    return true;
  }

  async function unlockStep(
    p: Extract<Phase, { name: 'unlock' }>,
    method: UnlockMethod,
    input?: string,
  ) {
    setBusy(true);
    setError(undefined);

    try {
      await finish(p.link, p.recovery, method, input);
    } finally {
      setBusy(false);
    }
  }

  async function handleSend(link: LinkDescription, account: ManagedAccount) {
    setBusy(true);
    setError(undefined);

    try {
      const recovery = await getUnlockableRecoverySecret();

      if (!recovery) {
        setPhase({
          name: 'failed',
          message:
            'This account has no backup yet. Create it in the web app first.',
        });

        return;
      }

      const methods = unlockMethods(recovery, account.email);

      // The account alone opens it when it can; otherwise ask for the passkey
      // or code below.
      if (
        methods[0] === 'assisted' &&
        (await finish(link, recovery, 'assisted', undefined, true))
      ) {
        return;
      }

      const rest = methods.filter(m => m !== 'assisted');

      if (rest.length === 0) {
        setPhase({
          name: 'failed',
          message:
            'This backup cannot be opened here. Restore it in the web app first.',
        });

        return;
      }

      setPhase({ name: 'unlock', link, recovery, methods: rest });
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Could not read your backup.',
      );
    } finally {
      setBusy(false);
    }
  }

  function handleCode(e: FormEvent, p: Extract<Phase, { name: 'unlock' }>) {
    e.preventDefault();

    if (!codeInput.trim()) return;

    void unlockStep(
      p,
      p.methods.includes('password') ? 'password' : 'code',
      codeInput,
    );
  }

  const onSignedIn = () => {
    setPhase({ name: 'loading' });
    setAttempt(n => n + 1);
  };

  return (
    <Shell>
      <OnboardingWrap>
        <OnboardingCard>
          <Column gap='1rem'>
            {phase.name === 'loading' || phase.name === 'sending' ? (
              <CardSubtitle>
                {phase.name === 'sending' ? 'Sending…' : 'Loading…'}
              </CardSubtitle>
            ) : null}

            {phase.name === 'sign-in' ? (
              <>
                <CardTitle>Sign in to continue</CardTitle>
                <CardSubtitle>
                  Sign in to your account to send your identity to your device.
                </CardSubtitle>
                {portalUrl && canHoldProviderCookie(portalUrl) ? (
                  <AccountSignInPanel
                    portalUrl={portalUrl}
                    onSignedIn={onSignedIn}
                  />
                ) : portalUrl ? (
                  <AccountSignInViaBrowser
                    portalUrl={portalUrl}
                    onSignedIn={onSignedIn}
                  />
                ) : (
                  <CardError role='alert'>
                    No account service is known here.
                  </CardError>
                )}
              </>
            ) : null}

            {phase.name === 'confirm' ? (
              <>
                <CardTitle>
                  Send your identity to {phase.link.deviceName}?
                </CardTitle>
                <CardSubtitle>
                  Only continue if you started this on your own device just now
                  and it shows code {code}.
                </CardSubtitle>
                <CardSubtitle>
                  Signed in as {accountAddress(phase.account)}.
                </CardSubtitle>
                {error ? <CardError role='alert'>{error}</CardError> : null}
                <CtaButton
                  disabled={busy}
                  onClick={() => void handleSend(phase.link, phase.account)}
                >
                  {busy ? 'Unlocking…' : 'Send'}
                </CtaButton>
              </>
            ) : null}

            {phase.name === 'unlock' ? (
              <>
                <CardTitle>Unlock your backup</CardTitle>
                {phase.methods.includes('passkey') ? (
                  <Button
                    type='button'
                    disabled={busy}
                    onClick={() => void unlockStep(phase, 'passkey')}
                  >
                    {busy
                      ? 'Waiting for your passkey…'
                      : 'Unlock with your passkey'}
                  </Button>
                ) : null}
                {phase.methods.includes('code') ||
                phase.methods.includes('password') ? (
                  <form onSubmit={e => handleCode(e, phase)}>
                    <Column gap='1rem'>
                      <InputWrapper>
                        <InputStyled
                          value={codeInput}
                          onChange={e => setCodeInput(e.target.value)}
                          type='password'
                          autoComplete='off'
                          spellCheck={false}
                          disabled={busy}
                          placeholder={
                            phase.methods.includes('password')
                              ? 'Recovery password'
                              : 'Recovery code'
                          }
                          aria-label='Recovery code'
                        />
                      </InputWrapper>
                      <Button
                        type='submit'
                        subtle
                        disabled={busy || !codeInput.trim()}
                      >
                        Send with this code
                      </Button>
                    </Column>
                  </form>
                ) : null}
                {error ? <CardError role='alert'>{error}</CardError> : null}
              </>
            ) : null}

            {phase.name === 'done' ? (
              <>
                <CardTitle>Done</CardTitle>
                <CardSubtitle>Go back to your device.</CardSubtitle>
              </>
            ) : null}

            {phase.name === 'failed' ? (
              <>
                <CardTitle>Could not send your identity</CardTitle>
                <CardError role='alert'>{phase.message}</CardError>
              </>
            ) : null}
          </Column>
        </OnboardingCard>
      </OnboardingWrap>
    </Shell>
  );
}
