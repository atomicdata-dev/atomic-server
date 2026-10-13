import { useState } from 'react';
import { createRoute } from '@tanstack/react-router';
import { agentSubjectFromPublicKey, grantAgent, useStore } from '@tomic/react';
import { styled } from 'styled-components';
import { Button } from '../components/Button';
import { Margin } from '../components/Card';
import { ConnectDrivePicker } from '../components/ConnectDrivePicker';
import { ContainerNarrow } from '../components/Containers';
import { ErrorLook } from '../components/ErrorLook';
import { Main } from '../components/Main';
import { Column, Row } from '../components/Row';
import { RadioInput } from '../components/forms/RadioInput';
import { useSettings } from '../helpers/AppSettings';
import { rememberConnectedApp } from '../helpers/connectedApps';
import { useAccountDriveCatalog } from '../hooks/useAccountDriveCatalog';
import { usePrivateDrive } from '../hooks/usePrivateDrive';
import { useSavedDrives } from '../hooks/useSavedDrives';
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
  const { privateDrive, loading: homeLoading } = usePrivateDrive();
  const [savedDrives] = useSavedDrives();
  const catalog = useAccountDriveCatalog(
    privateDrive ? [privateDrive, ...savedDrives] : savedDrives,
  );

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
      <Page>
        <h1>Connect an app</h1>
        <p>
          This link is missing the app&apos;s key. Start again from the app that
          sent you here.
        </p>
      </Page>
    );
  }

  if (!agent?.subject) {
    return (
      <Page>
        <h1>Connect an app</h1>
        <p>Sign in first, then open this link again.</p>
        <Button onClick={() => navigate(paths.welcome)}>Sign in</Button>
      </Page>
    );
  }

  if (done) {
    return (
      <Page>
        <h1>Connected</h1>
        <p data-test='connect-agent-done'>
          {name} can now {write ? 'read and edit' : 'read'} what you shared. You
          can go back to it. To stop it, revoke it under Connected apps in your
          account settings.
        </p>
        <Button subtle onClick={() => navigate(paths.agentSettings)}>
          Account settings
        </Button>
      </Page>
    );
  }

  const toggle = (subject: string, on: boolean) =>
    setPicked(
      on
        ? [...selected, subject]
        : selected.filter(existing => existing !== subject),
    );

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
    <Page>
      <h1>Connect an app</h1>
      <p>
        <strong data-test='connect-agent-name'>{name}</strong> asks to use your
        Atomic data. It has its own key, so your secret stays with you, and you
        can revoke it at any time.
      </p>

      <Column>
        <Heading>What it can reach</Heading>
        <ConnectDrivePicker
          subjects={catalog.subjects}
          selected={selected}
          onToggle={toggle}
        />

        <Heading>What it can do</Heading>
        <Column gap='0.75rem'>
          <RadioInput
            name='access'
            checked={!write}
            onChange={() => setWrite(false)}
          >
            Read only
          </RadioInput>
          <RadioInput
            name='access'
            checked={write}
            onChange={() => setWrite(true)}
            data-test='connect-agent-write'
          >
            Read and edit
          </RadioInput>
        </Column>

        <Margin />
        {error && <ErrorLook>{error}</ErrorLook>}
        <Row>
          <Button
            onClick={handleAllow}
            disabled={busy || homeLoading || selected.length === 0}
            loading={busy ? 'Connecting' : undefined}
            data-test='connect-agent-allow'
          >
            Allow
          </Button>
          <Button subtle onClick={() => navigate(paths.agentSettings)}>
            Cancel
          </Button>
        </Row>
      </Column>
    </Page>
  );
}

function Page({ children }: React.PropsWithChildren) {
  return (
    <Main>
      <ContainerNarrow>{children}</ContainerNarrow>
    </Main>
  );
}

const Heading = styled.h2`
  margin: 0;
  font-size: 1.1rem;
`;
