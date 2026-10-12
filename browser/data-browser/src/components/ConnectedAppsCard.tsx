import { useCallback, useEffect, useState } from 'react';
import {
  core,
  grantsTo,
  revokeAgent,
  useResource,
  useStore,
  type AgentGrant,
} from '@tomic/react';
import { styled } from 'styled-components';
import { Button } from './Button';
import { Card } from './Card';
import { ErrorLook } from './ErrorLook';
import {
  forgetConnectedApp,
  listConnectedApps,
} from '../helpers/connectedApps';

/**
 * The apps the person let use their data (see ConnectAgentRoute), each with
 * what it can reach and a Revoke button. What it can reach is read from the
 * ACLs, so the list cannot drift from what the app can actually open.
 */
export function ConnectedAppsCard({ home }: { home: string }) {
  const store = useStore();
  const [apps, setApps] = useState<string[]>();

  const refresh = useCallback(() => {
    listConnectedApps(store, home)
      .then(setApps)
      .catch(() => setApps([]));
  }, [store, home]);

  useEffect(refresh, [refresh]);

  if (!apps) {
    return null;
  }

  if (apps.length === 0) {
    return (
      <Muted data-test='connected-apps-empty'>
        No apps yet. An AI assistant connected through the Atomic MCP server
        shows up here.
      </Muted>
    );
  }

  return (
    <Card data-test='connected-apps'>
      <List>
        {apps.map(subject => (
          <ConnectedApp
            key={subject}
            subject={subject}
            home={home}
            onRevoked={refresh}
          />
        ))}
      </List>
    </Card>
  );
}

function ConnectedApp({
  subject,
  home,
  onRevoked,
}: {
  subject: string;
  home: string;
  onRevoked: () => void;
}) {
  const store = useStore();
  const [name, setName] = useState<string>();
  const [grants, setGrants] = useState<AgentGrant[]>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    // Only what the person shared. What the app created itself it can also
    // edit, and revoking takes that away too, but listing it here is noise.
    grantsTo(store, subject)
      .then(all => setGrants(all.filter(grant => grant.read)))
      .catch(() => setGrants([]));

    // The app names itself on its own Agent resource. Ask the server: a copy
    // cached on this device may predate the app setting its name.
    store
      .fetchResourceFromServer(subject, { noWebSocket: true })
      .then(profile =>
        setName(profile.get(core.properties.name) as string | undefined),
      )
      .catch(() => undefined);
  }, [store, subject]);

  async function handleRevoke() {
    setBusy(true);
    setError(undefined);

    try {
      const report = await revokeAgent(store, subject);

      if (report.failed.length > 0) {
        setError(
          `Still has access to ${report.failed.length} ${
            report.failed.length === 1 ? 'resource' : 'resources'
          }: ${report.failed.map(f => f.reason).join('; ')}`,
        );
      } else {
        await forgetConnectedApp(store, home, subject);
        onRevoked();
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }

    setBusy(false);
  }

  const label = name ?? `App ${subject.slice(-8)}`;
  const canEdit = grants?.some(grant => grant.write);

  return (
    <Item>
      <Details>
        <strong>{label}</strong>
        <Muted>
          {grants === undefined
            ? '…'
            : grants.length === 0
              ? 'No access left'
              : grants.map((grant, i) => (
                  <span key={grant.subject}>
                    {i > 0 && ', '}
                    <TargetName subject={grant.subject} />
                  </span>
                ))}
          {canEdit ? ' · can edit' : grants?.length ? ' · read only' : ''}
        </Muted>
        {error && <ErrorLook>{error}</ErrorLook>}
      </Details>
      <Button
        subtle
        onClick={handleRevoke}
        disabled={busy}
        loading={busy ? 'Revoking' : undefined}
        data-test='connected-app-revoke'
      >
        Revoke
      </Button>
    </Item>
  );
}

function TargetName({ subject }: { subject: string }) {
  const resource = useResource(subject);

  return <>{resource.loading ? '…' : resource.title}</>;
}

const List = styled.div`
  display: flex;
  flex-direction: column;
  gap: 1rem;
`;

const Item = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
`;

const Details = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  min-width: 0;
`;

const Muted = styled.span`
  color: ${p => p.theme.colors.textLight};
`;
