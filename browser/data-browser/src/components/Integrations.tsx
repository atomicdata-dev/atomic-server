import { useEffect, useState } from 'react';
import { signRequest, useStore, urls, type Agent } from '@tomic/react';
import { Button } from './Button';
import { Card } from './Card';
import { Column, Row } from './Row';
import { AtomicLink } from './AtomicLink';
import { fetchPrivateDriveSubject } from '../helpers/privateDrive';

type Integration = {
  id: string;
  label: string;
  configured: boolean;
  job?: {
    status: 'authorizing' | 'importing' | 'complete' | 'failed';
    message: string;
    drive?: string;
  };
};

export function Integrations({ server }: { server: string }) {
  const store = useStore();
  const agent = store.getAgent();

  return (
    <IntegrationList
      key={`${server}:${agent?.subject}`}
      server={server}
      agent={agent}
    />
  );
}

function IntegrationList({ server, agent }: { server: string; agent?: Agent }) {
  const store = useStore();
  const [items, setItems] = useState<Integration[]>([]);
  const [error, setError] = useState<string>();
  const [starting, setStarting] = useState<string>();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;

    async function load() {
      if (!agent) {
        return;
      }

      try {
        const url = new URL('/integrations', server).toString();
        const headers = await signRequest(url, agent, {});
        const response = await fetch(url, { headers, credentials: 'include' });
        if (!response.ok)
          throw new Error('Unable to load integrations from this server.');
        const data: Integration[] = await response.json();
        if (cancelled) return;
        setItems(data);
        const imported = data.flatMap(item =>
          item.job?.status === 'complete' && item.job.drive
            ? [item.job.drive]
            : [],
        );

        if (imported.length) {
          const subject = await fetchPrivateDriveSubject(store, agent);
          if (!subject)
            throw new Error('Set up a private drive to save imported drives.');
          const home = await store.getResource(subject);
          if (cancelled) return;
          const saved = home.getArray(urls.properties.drives);
          const missing = imported.filter(drive => !saved.includes(drive));

          if (missing.length) {
            await home.set(urls.properties.drives, [...saved, ...missing]);
            await home.save();
          }
        }

        setError(undefined);
      } catch (e) {
        if (!cancelled) setError((e as Error).message);
      } finally {
        if (!cancelled) {
          setLoading(false);
          timer = setTimeout(load, 3000);
        }
      }
    }

    void load();

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [server, agent, store]);

  async function connect(integration: Integration) {
    if (!agent) return;
    setStarting(integration.id);
    setError(undefined);

    try {
      const url = new URL('/integrations/start', server);
      url.searchParams.set('integration', integration.id);
      const headers = await signRequest(url.toString(), agent, {});
      const response = await fetch(url, {
        method: 'POST',
        headers,
        credentials: 'include',
      });
      const data = await response.json();
      if (!response.ok)
        throw new Error(data.error ?? 'Unable to start authorization.');
      window.location.assign(data.url);
    } catch (e) {
      setError((e as Error).message);
      setStarting(undefined);
    }
  }

  return (
    <section aria-labelledby='integrations-heading'>
      <h2 id='integrations-heading'>Integrations</h2>
      <Card>
        <Column>
          <p>Connect an account to import its data into this server.</p>
          {!agent && <p>Sign in to connect an integration.</p>}
          {agent && loading && <p role='status'>Loading integrations…</p>}
          {error && <p role='alert'>{error}</p>}
          {agent && !loading && !error && items.length === 0 && (
            <p>No integrations are configured on this server.</p>
          )}
          {items.map(item => (
            <Row key={item.id} wrapItems>
              <Button
                disabled={
                  !item.configured ||
                  !!starting ||
                  item.job?.status === 'importing'
                }
                loading={starting === item.id ? 'Connecting…' : undefined}
                onClick={() => connect(item)}
              >
                {item.label}
              </Button>
              {!item.configured && (
                <span>OAuth setup needed on the server</span>
              )}
              {item.job && (
                <span role={item.job.status === 'failed' ? 'alert' : 'status'}>
                  {item.job.message}
                </span>
              )}
              {item.job?.drive && (
                <AtomicLink subject={item.job.drive}>
                  Open imported data
                </AtomicLink>
              )}
            </Row>
          ))}
        </Column>
      </Card>
    </section>
  );
}
