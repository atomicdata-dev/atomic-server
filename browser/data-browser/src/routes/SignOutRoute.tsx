import { createRoute, useNavigate } from '@tanstack/react-router';
import { useEffect, useRef, useState, type JSX } from 'react';
import { appRoute } from './RootRoutes';
import { pathNames, paths } from './paths';
import { useSettings } from '../helpers/AppSettings';
import { Shell } from '../views/getting-started/chrome';
import { Button } from '../components/Button';
import { Column } from '../components/Row';
import {
  cameFromPortal,
  portalReturnUrl,
  signOutEverywhere,
} from '../helpers/managed/signOut';

/**
 * Signing out on the account portal passes through here, so the identity's
 * key leaves this browser too: one sign-in, one sign-out. Coming from the
 * portal it signs out straight away and goes back; any other page that links
 * here has to ask first, so a link cannot sign anyone out.
 */
export const SignOutRoute = createRoute({
  path: pathNames.signOut,
  getParentRoute: () => appRoute,
  validateSearch: (search: Record<string, unknown>): { return?: string } => ({
    return: typeof search.return === 'string' ? search.return : undefined,
  }),
  component: SignOutPage,
});

function SignOutPage(): JSX.Element {
  const { agent, setAgent, setDrive } = useSettings();
  const navigate = useNavigate();
  const { return: returnTo } = SignOutRoute.useSearch();
  const [busy, setBusy] = useState(false);
  const started = useRef(false);

  async function signOut() {
    if (started.current) return;
    started.current = true;
    setBusy(true);
    await signOutEverywhere({ agentSubject: agent?.subject });
    setAgent(undefined);
    setDrive('');
    const back = portalReturnUrl(returnTo);

    if (back) window.location.replace(back);
    else navigate({ to: paths.welcome, replace: true });
  }

  useEffect(() => {
    if (cameFromPortal()) void signOut();
  }, []);

  return (
    <Shell>
      <Column>
        <h1>Sign out</h1>
        <p>
          This signs you out of your account and removes your key from this
          browser.
        </p>
        <Button disabled={busy} onClick={() => void signOut()}>
          {busy ? 'Signing out…' : 'Sign out'}
        </Button>
      </Column>
    </Shell>
  );
}
