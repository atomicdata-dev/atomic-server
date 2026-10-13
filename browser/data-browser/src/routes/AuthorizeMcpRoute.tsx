import { useState } from 'react';
import { createRoute } from '@tanstack/react-router';
import { grantAgent, useStore } from '@tomic/react';
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
import {
  approveAuthorization,
  isTrustedServer,
  requestIssuedAgent,
} from '../helpers/hostedMcp';
import { isRunningInTauri } from '../helpers/tauri';
import { useAccountDriveCatalog } from '../hooks/useAccountDriveCatalog';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { usePrivateDrive } from '../hooks/usePrivateDrive';
import { useSavedDrives } from '../hooks/useSavedDrives';
import { pathNames, paths } from './paths';
import { appRoute } from './RootRoutes';

export interface AuthorizeMcpSearch {
  server: string;
  client_id: string;
  client_name: string;
  redirect_uri: string;
  code_challenge: string;
  /** `read write` when the client asks to edit, which only sets the default. */
  scope?: string;
  state?: string;
}

const text = (value: unknown) => (typeof value === 'string' ? value : '');

/**
 * /app/authorize-mcp?server=&client_id=&client_name=&redirect_uri=&code_challenge=[&state=]
 *
 * Where a person lets an MCP client that runs elsewhere (claude.ai, for one)
 * read, and if they allow it edit, their data. The node's `/oauth/authorize` sends the browser here. On
 * Allow the app asks the node for an identity for that client, gives it read
 * rights on the drives picked (to edit as well, if allowed), and sends the
 * browser back to the client. The client can only reach what is picked here;
 * revoke it under Connected apps in account settings.
 */
export const AuthorizeMcpRoute = createRoute({
  path: pathNames.authorizeMcp,
  component: () => <AuthorizeMcpPage />,
  getParentRoute: () => appRoute,
  validateSearch: (search): AuthorizeMcpSearch => ({
    server: text(search.server),
    client_id: text(search.client_id),
    client_name: text(search.client_name),
    redirect_uri: text(search.redirect_uri),
    code_challenge: text(search.code_challenge),
    scope: text(search.scope) || undefined,
    state: text(search.state) || undefined,
  }),
});

function isLoopback(uri: string): boolean {
  try {
    return ['127.0.0.1', 'localhost', '[::1]'].includes(new URL(uri).hostname);
  } catch {
    return false;
  }
}

function hostOf(uri: string): string | undefined {
  try {
    const url = new URL(uri);

    return url.host || url.protocol;
  } catch {
    return undefined;
  }
}

function AuthorizeMcpPage() {
  const store = useStore();
  const navigate = useNavigateWithTransition();
  const { agent, drive } = useSettings();
  const search = AuthorizeMcpRoute.useSearch();
  const { privateDrive, loading: homeLoading } = usePrivateDrive();
  const [savedDrives] = useSavedDrives();
  const catalog = useAccountDriveCatalog(
    privateDrive ? [privateDrive, ...savedDrives] : savedDrives,
  );
  const [picked, setPicked] = useState<string[] | undefined>();
  const [write, setWrite] = useState<boolean | undefined>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const name = search.client_name.trim() || 'An app';
  const host = hostOf(search.redirect_uri);
  const serverHost = hostOf(search.server);
  const trusted =
    !!search.server &&
    isTrustedServer(search.server, [
      window.location.origin,
      store.getServerUrl(),
      drive,
      privateDrive,
    ]);
  const selected =
    picked ?? (drive && catalog.subjects.includes(drive) ? [drive] : []);
  const canEdit = write ?? search.scope?.split(' ').includes('write') === true;
  const action = canEdit ? 'read and edit' : 'read';
  const complete =
    search.server &&
    search.client_id &&
    search.redirect_uri &&
    search.code_challenge;

  if (!complete || !host) {
    return (
      <Page>
        <h1>Connect an app</h1>
        <p>
          This link is incomplete. Start again from the app that sent you here.
        </p>
      </Page>
    );
  }

  if (!trusted) {
    return (
      <Page>
        <h1>Connect an app</h1>
        <p>
          This link points at {serverHost ?? 'an unknown server'}, which is not
          the server you are signed in to, so nothing was shared. Start again
          from the app that sent you here, using your own server.
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

      const issued = await requestIssuedAgent(
        store,
        search.server,
        search.client_id,
      );

      await grantAgent(store, issued.agent, selected, canEdit);
      await rememberConnectedApp(store, home, issued.agent);

      const redirect = await approveAuthorization(store, search.server, {
        clientId: search.client_id,
        redirectUri: search.redirect_uri,
        codeChallenge: search.code_challenge,
        nonce: issued.nonce,
        write: canEdit,
        state: search.state,
      });

      if (isRunningInTauri() && isLoopback(redirect)) {
        // The client listens on this machine: tell it, and stay in the app
        // rather than navigating the window away from it.
        await fetch(redirect, { mode: 'no-cors' });
        navigate(paths.agentSettings);

        return;
      }

      // Away from the app: the client takes over from here.
      window.location.assign(redirect);

      return;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }

    setBusy(false);
  }

  return (
    <Page>
      <h1>Connect an app that returns to {host}</h1>
      <p>
        <strong data-test='authorize-mcp-name'>{name}</strong> asks to {action}
        your data on {serverHost}.
      </p>
      <p>
        When you allow it, you go back to {host}. The name is chosen by the app,
        so only allow it if that is where you expect to go. It gets its own
        access, so your secret stays with you, and you can revoke it at any
        time.
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
            checked={!canEdit}
            onChange={() => setWrite(false)}
          >
            Read only
          </RadioInput>
          <RadioInput
            name='access'
            checked={canEdit}
            onChange={() => setWrite(true)}
            data-test='authorize-mcp-write'
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
            data-test='authorize-mcp-allow'
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
