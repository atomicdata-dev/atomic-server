import { useState } from 'react';
import { createRoute } from '@tanstack/react-router';
import { agentSubjectFromPublicKey, grantAgent, useStore } from '@tomic/react';
import { Button } from '../components/Button';
import {
  ConnectAppForm,
  ConnectPage,
  toggleSubject,
  useConnectableDrives,
} from '../components/ConnectAppForm';
import { useSettings } from '../helpers/AppSettings';
import { rememberConnectedApp } from '../helpers/connectedApps';
import { signInPath } from '../helpers/returnPath';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { pathNames, paths } from './paths';
import { appRoute } from './RootRoutes';

export interface ConnectAgentSearch {
  key: string;
  name: string;
  /** Hints from the app (see `connectAgentUrl`): the person still decides. */
  write?: boolean;
  target?: string[];
}

/**
 * /app/connect-agent?key=<public key>&name=<label>[&write=1][&target=<subject>]
 *
 * Where a person lets any app that made its own key (the Atomic MCP server,
 * a CLI, a script) use some of their data. Apps build the link with
 * `connectAgentUrl` from @tomic/lib and wait with `waitForGrant`. The app never sees the
 * person's secret: it keeps its own key, and gets read or write rights on the
 * drives picked here, revocable from account settings. The name comes from the
 * link and is the app's own claim; the key is what the rights are bound to.
 */
export const ConnectAgentRoute = createRoute({
  path: pathNames.connectAgent,
  component: () => <ConnectAgentPage />,
  getParentRoute: () => appRoute,
  validateSearch: (search): ConnectAgentSearch => ({
    key: typeof search.key === 'string' ? search.key : '',
    name: typeof search.name === 'string' ? search.name : '',
    write: search.write === 1 || search.write === '1' || search.write === true,
    target: (Array.isArray(search.target)
      ? search.target
      : [search.target]
    ).filter((t): t is string => typeof t === 'string' && t.length > 0),
  }),
});

function ConnectAgentPage() {
  const store = useStore();
  const navigate = useNavigateWithTransition();
  const { agent, drive } = useSettings();
  const {
    key,
    name: requestedName,
    write: requestedWrite,
    target: requestedTargets,
  } = ConnectAgentRoute.useSearch();
  const { privateDrive, homeLoading, catalog } = useConnectableDrives();

  const name = requestedName.trim() || 'An app';
  const [picked, setPicked] = useState<string[] | undefined>();
  const [write, setWrite] = useState(!!requestedWrite);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [done, setDone] = useState(false);

  // Until the person touches the list, offer what the app asked for, or else
  // the drive they are on. Only drives of theirs can be offered either way.
  const asked = (requestedTargets ?? []).filter(t =>
    catalog.subjects.includes(t),
  );
  const selected =
    picked ??
    (asked.length > 0
      ? asked
      : drive && catalog.subjects.includes(drive)
        ? [drive]
        : []);

  let keySubject: string | undefined;

  try {
    keySubject = key ? agentSubjectFromPublicKey(key).subject : undefined;
  } catch {
    keySubject = undefined;
  }

  if (!keySubject) {
    return (
      <ConnectPage>
        <h1>Connect an app</h1>
        <p>
          This link is missing the app&apos;s key. Start again from the app that
          sent you here.
        </p>
      </ConnectPage>
    );
  }

  if (!agent?.subject) {
    return (
      <ConnectPage>
        <h1>Connect an app</h1>
        <p>Sign in first, then open this link again.</p>
        <Button onClick={() => navigate(signInPath(window.location))}>
          Sign in
        </Button>
      </ConnectPage>
    );
  }

  if (done) {
    return (
      <ConnectPage>
        <h1>Connected</h1>
        <p data-test='connect-agent-done'>
          {name} can now {write ? 'read and edit' : 'read'} what you shared. You
          can go back to it. To stop it, revoke it under Connected apps in your
          account settings.
        </p>
        <Button subtle onClick={() => navigate(paths.agentSettings)}>
          Account settings
        </Button>
      </ConnectPage>
    );
  }

  async function handleAllow() {
    setBusy(true);
    setError(undefined);

    try {
      const home = privateDrive ?? drive;

      if (!home) {
        throw new Error('Open one of your drives first.');
      }

      await grantAgent(store, keySubject!, selected, write);
      await rememberConnectedApp(store, home, keySubject!);
      setDone(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }

    setBusy(false);
  }

  return (
    <ConnectPage>
      <h1>Connect an app</h1>
      <p>
        <strong data-test='connect-agent-name'>{name}</strong> asks to use your
        Atomic data. It has its own key, so your secret stays with you, and you
        can revoke it at any time.
      </p>

      <ConnectAppForm
        subjects={catalog.subjects}
        selected={selected}
        onToggle={(subject, on) =>
          setPicked(toggleSubject(selected, subject, on))
        }
        onToggleAll={on => setPicked(on ? catalog.subjects : [])}
        canEdit={write}
        onCanEditChange={setWrite}
        error={error}
        busy={busy}
        disabled={homeLoading}
        onAllow={handleAllow}
        onCancel={() => navigate(paths.agentSettings)}
        testId='connect-agent'
      />
    </ConnectPage>
  );
}
