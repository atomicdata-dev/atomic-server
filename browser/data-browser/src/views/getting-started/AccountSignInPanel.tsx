import { useEffect, useRef, useState, type FormEvent } from 'react';
import { styled, useTheme } from 'styled-components';
import { AccountSignIn } from '@tomic/service-ui';
import '@tomic/service-ui/styles.css';
import {
  getAccountProviders,
  providerSignInUrl,
  sendAccountEmailLink,
  type AccountProviders,
  type SignInProvider,
} from '../../helpers/managed/accountProviders';
import { signInWithAccountPasskey } from '../../helpers/managed/accountPasskey';
import {
  getManagedAccount,
  noteManagedSessionChanged,
} from '../../helpers/managed/session';
import {
  deviceCanUsePasskeys,
  hasPasskeyApi,
} from '../../helpers/passkeySupport';
import {
  approvalUrl,
  awaitDeviceLink,
  newReturnVerifier,
  parseAccountReturn,
  redeemDeviceLink,
  requestDeviceLink,
  type LinkRequest,
} from '../../helpers/managed/deviceLink';
import { setAccountReturnHandler } from '../../helpers/deepLinkQueue';
import { openExternal } from '../../helpers/openExternal';
import { isRunningInTauri } from '../../helpers/tauri';
import { CardError } from './chrome';

const EMAIL_POLL_MS = 2000;

/** undefined while the device is still being asked. */
function usePasskeysOnThisDevice(): boolean | undefined {
  const [usable, setUsable] = useState<boolean | undefined>(() =>
    hasPasskeyApi() ? undefined : false,
  );

  useEffect(() => {
    let active = true;

    void deviceCanUsePasskeys().then(result => {
      if (active) setUsable(result);
    });

    return () => {
      active = false;
    };
  }, []);

  return usable;
}

const NO_PROVIDERS: AccountProviders = {
  google: false,
  apple: false,
  github: false,
  assisted_recovery: false,
};

/**
 * The account's ways in, the same component and the same options as the
 * portal's sign-in page: Google, Apple, GitHub, passkey, email link. `onSignedIn` runs once
 * this browser holds an account session, however it got one.
 */
export function AccountSignInPanel({
  portalUrl,
  disabled,
  onSignedIn,
}: {
  portalUrl: string;
  disabled?: boolean;
  onSignedIn: () => void;
}) {
  const theme = useTheme();
  const [providers, setProviders] = useState<AccountProviders>(NO_PROVIDERS);
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [sending, setSending] = useState(false);
  const [sentTo, setSentTo] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const passkeys = usePasskeysOnThisDevice();
  const signedIn = useRef(onSignedIn);

  useEffect(() => {
    signedIn.current = onSignedIn;
  });

  useEffect(() => {
    let live = true;
    void getAccountProviders().then(p => live && setProviders(p));

    return () => {
      live = false;
    };
  }, []);

  // The email link opens on the portal, in another tab or on the phone that
  // got the mail. The shared cookie is how this page hears about it.
  useEffect(() => {
    if (!sentTo) return;

    const timer = window.setInterval(() => {
      void getManagedAccount({ fresh: true })
        .catch(() => null)
        .then(account => {
          if (account) {
            noteManagedSessionChanged();
            window.clearInterval(timer);
            signedIn.current();
          }
        });
    }, EMAIL_POLL_MS);

    return () => window.clearInterval(timer);
  }, [sentTo]);

  async function handlePasskey() {
    setBusy(true);
    setError(null);

    const outcome = await signInWithAccountPasskey(email).catch(
      (err: unknown) => (err instanceof Error ? err : new Error(String(err))),
    );
    setBusy(false);

    if (outcome instanceof Error) setError(outcome.message);
    else if (outcome) onSignedIn();
  }

  async function handleEmail(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSending(true);
    setError(null);

    const outcome = await sendAccountEmailLink(email).catch((err: unknown) =>
      err instanceof Error ? err : new Error(String(err)),
    );
    setSending(false);

    if (outcome instanceof Error) {
      setError(outcome.message);

      return;
    }

    // Local development hands the link out instead of mailing it, built on
    // the requesting origin; the mailed one always opens on the portal.
    if (outcome) {
      const link = new URL(outcome);
      window.open(
        new URL(link.pathname + link.search, portalUrl).toString(),
        '_blank',
        'noopener',
      );
    }

    setSentTo(email.trim());
  }

  const href = (provider: SignInProvider) =>
    providers[provider]
      ? providerSignInUrl(provider, portalUrl, window.location.href)
      : null;

  return (
    <Themed>
      <AccountSignIn
        googleHref={href('google')}
        appleHref={href('apple')}
        githubHref={href('github')}
        onPasskey={() => void handlePasskey()}
        passkeySupported={passkeys === true}
        email={email}
        onEmailChange={setEmail}
        onSubmitEmail={e => void handleEmail(e)}
        busy={busy || disabled}
        sending={sending}
        theme={theme.darkMode ? 'dark' : 'light'}
        assistedRecovery={providers.assisted_recovery}
        notice={
          error ? (
            <CardError role='alert'>{error}</CardError>
          ) : sentTo ? (
            <Sent role='status'>
              We sent a link to {sentTo}. Open it, then come back here: this
              page continues by itself.
            </Sent>
          ) : null
        }
      />
    </Themed>
  );
}

const Themed = styled.div`
  --service-accent: ${p => p.theme.colors.main};
  --service-surface: ${p => p.theme.colors.bg};
  --service-on-accent: ${p => p.theme.colors.bg};
  --service-muted: ${p => p.theme.colors.textLight};
  --service-text: ${p => p.theme.colors.text};
  --service-border: ${p => p.theme.colors.bg2};
  --service-input-bg: ${p => p.theme.colors.bg};
  --service-radius: ${p => p.theme.radius};
`;

const Sent = styled.p`
  margin: 0;
  font-size: 0.9rem;
  color: ${p => p.theme.colors.textLight};
`;

/**
 * The same options for an app that cannot hold the account cookie (the
 * desktop and Android apps, a self-hosted origin): each one opens the
 * portal in the system browser, straight at that option, with a device-link
 * code, and this screen continues once the code is approved there. Google
 * refuses to sign in inside an app window anyway, and Apple's answer is a
 * POST no app window could receive.
 */
export function AccountSignInViaBrowser({
  portalUrl,
  disabled,
  onSignedIn,
}: {
  portalUrl: string;
  disabled?: boolean;
  onSignedIn: () => void;
}) {
  const theme = useTheme();
  const [providers, setProviders] = useState<AccountProviders>(NO_PROVIDERS);
  const [email, setEmail] = useState('');
  const [request, setRequest] = useState<LinkRequest | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const waiting = useRef<AbortController | null>(null);
  const signedIn = useRef(onSignedIn);
  /** The request in flight and, for an app the provider can send back to,
   * the verifier only this app holds. */
  const pending = useRef<{ request: LinkRequest; verifier?: string } | null>(
    null,
  );

  useEffect(() => {
    signedIn.current = onSignedIn;
  });

  useEffect(() => {
    let live = true;
    void getAccountProviders().then(p => live && setProviders(p));

    // Signed in in the browser, which sent the handoff back through
    // atomic://. Only this request's own handoff, redeemed with its verifier,
    // can finish it; anything else is ignored.
    const stopListening = setAccountReturnHandler(uri => {
      const back = parseAccountReturn(uri);
      const current = pending.current;

      if (!back || !current?.verifier) return;
      if (back.code !== current.request.user_code) return;

      void redeemDeviceLink(
        portalUrl,
        current.request.device_code,
        back.handoff,
        current.verifier,
      )
        .catch(() => false)
        .then(ok => {
          if (!ok || !live) return;

          pending.current = null;
          waiting.current?.abort();
          waiting.current = null;
          setRequest(null);
          signedIn.current();
        });
    });

    return () => {
      live = false;
      stopListening();
      waiting.current?.abort();
    };
  }, [portalUrl]);

  function wait(issued: LinkRequest) {
    if (waiting.current) return;

    const controller = new AbortController();
    waiting.current = controller;

    void awaitDeviceLink(portalUrl, issued, { signal: controller.signal })
      .catch(() => 'expired' as const)
      .then(outcome => {
        waiting.current = null;
        pending.current = null;
        setRequest(null);

        if (controller.signal.aborted) return;

        if (outcome === 'linked') signedIn.current();
        else setError('That sign-in expired. Pick an option to start again.');
      });
  }

  async function open(via: SignInProvider | 'passkey' | 'email') {
    setBusy(true);
    setError(null);

    // The desktop and Android apps can be sent back to through atomic://,
    // so signing in there is enough; a browser app keeps the code.
    const sendBack = isRunningInTauri();
    const returnVerifier = sendBack ? newReturnVerifier() : undefined;
    const issued =
      request ??
      (await requestDeviceLink(
        portalUrl,
        undefined,
        returnVerifier?.challenge,
      ).catch((err: unknown) =>
        err instanceof Error ? err : new Error(String(err)),
      ));
    setBusy(false);

    if (issued instanceof Error) {
      setError(
        issued instanceof TypeError
          ? 'Could not reach your account. Check your connection and try again.'
          : issued.message,
      );

      return;
    }

    if (!request) {
      pending.current = { request: issued, verifier: returnVerifier?.verifier };
    }

    setRequest(issued);
    const url = new URL(approvalUrl(portalUrl, issued.user_code));
    url.searchParams.set('via', via);

    if (pending.current?.verifier) url.searchParams.set('return', 'app');

    if (via === 'email' && email.trim()) {
      url.searchParams.set('email', email.trim());
    }

    await openExternal(url.toString());
    wait(issued);
  }

  return (
    <Themed>
      <AccountSignIn
        googleHref={null}
        onGoogle={providers.google ? () => void open('google') : undefined}
        appleHref={null}
        onApple={providers.apple ? () => void open('apple') : undefined}
        githubHref={null}
        onGitHub={providers.github ? () => void open('github') : undefined}
        onPasskey={() => void open('passkey')}
        email={email}
        onEmailChange={setEmail}
        onSubmitEmail={e => {
          e.preventDefault();
          void open('email');
        }}
        busy={busy || disabled}
        theme={theme.darkMode ? 'dark' : 'light'}
        assistedRecovery={providers.assisted_recovery}
        notice={
          error ? (
            <CardError role='alert'>{error}</CardError>
          ) : request ? (
            <Sent role='status' data-testid='link-user-code'>
              Finish in your browser, then approve the code{' '}
              <strong>{request.user_code}</strong>. This screen continues by
              itself.
            </Sent>
          ) : null
        }
      />
    </Themed>
  );
}
