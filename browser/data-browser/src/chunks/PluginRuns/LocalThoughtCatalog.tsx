import { useEffect, useState, useRef, lazy, Suspense } from 'react';
import { useStore } from '@tomic/react';
import { Card } from '@components/Card';
import { Column } from '@components/Row';
import { Button } from '@components/Button';
import { Dialog, useDialog } from '@components/Dialog';
import { ErrMessage } from '@components/forms/InputStyles';
import { ConnectLocalThought } from './ConnectLocalThought';
import {
  browserIntegrations,
  connectionKey,
  platformName,
  proxyRequest,
} from './localThought';

const DirectGitHub = lazy(() =>
  import('./ConnectGitHub').then(m => ({ default: m.ConnectGitHub })),
);

export function LocalThoughtCatalog({
  drive,
  search,
}: {
  drive?: string;
  search: string;
}) {
  const store = useStore();
  const [platforms, setPlatforms] = useState<string[]>();
  const [error, setError] = useState('');
  const [returned, setReturned] = useState<string>();
  const completing = useRef(false);
  useEffect(() => {
    const controller = new AbortController();
    browserIntegrations()
      .catalog(controller.signal)
      .then(setPlatforms)
      .catch(reason => {
        if (!controller.signal.aborted) setError(String(reason));
      });

    return () => controller.abort();
  }, [store]);
  useEffect(() => {
    if (!drive || completing.current) return;
    const url = new URL(location.href);
    const state = url.searchParams.get('integration_state');
    const code = url.searchParams.get('connection_code');
    if (!state) return;
    completing.current = true;
    // Remove the single-use credential before fetching anything else or following links.
    history.replaceState(history.state, '', `${url.pathname}`);

    const finish = async () => {
      const raw = sessionStorage.getItem('localthought-pending');
      const pending = raw ? JSON.parse(raw) : undefined;
      const actor = store.getAgent()?.subject;
      if (
        !pending ||
        pending.state !== state ||
        pending.drive !== drive ||
        pending.actor !== actor ||
        !code
      )
        throw new Error(
          'Connection return is missing, expired or belongs to another account. Start connecting again.',
        );
      const result = await proxyRequest<{
        connection: string;
        platform: string;
      }>(store, 'finish', { drive, state, connectionCode: code });
      if (result.platform !== pending.platform)
        throw new Error(
          'Returned platform did not match the requested platform',
        );
      localStorage.setItem(
        connectionKey(drive, actor!, result.platform),
        JSON.stringify({
          ...result,
          drive,
          actor,
          installationConnection: pending.installationConnection,
        }),
      );
      sessionStorage.removeItem('localthought-pending');
      setReturned(result.platform);
    };

    void finish().catch(reason => setError(String(reason)));
  }, [drive, store]);
  const visible = platforms?.filter(id =>
    `${id} ${platformName(id)} ${id === 'github-issues' ? 'kanban tasks' : ''}`
      .toLowerCase()
      .includes(search.toLowerCase()),
  );

  return (
    <>
      {error && <ErrMessage role='alert'>{error}</ErrMessage>}
      {!platforms && !error && <p>Loading LocalThought platforms…</p>}
      {visible?.map(platform => (
        <PlatformCard
          key={`${platform}:${returned}`}
          platform={platform}
          drive={drive}
          returned={returned === platform}
        />
      ))}
    </>
  );
}

function PlatformCard({
  platform,
  drive,
  returned,
}: {
  platform: string;
  drive?: string;
  returned: boolean;
}) {
  const [dialog, show, , isOpen] = useDialog();
  const [direct, setDirect] = useState(false);
  useEffect(() => {
    if (returned) show();
  }, [returned, show]);

  return (
    <Card data-integration={platform}>
      <Column gap='0.75rem'>
        <h2>{platformName(platform)}</h2>
        <p>
          Connect your account through LocalThought and import records into your
          drive.
        </p>
        <Button disabled={!drive} onClick={show}>
          Set up connection
        </Button>
      </Column>
      <Dialog {...dialog} width='38rem'>
        <Dialog.Title>
          <h2>{platformName(platform)}</h2>
        </Dialog.Title>
        <Dialog.Content>
          {isOpen && drive && (
            <Suspense fallback={<p>Loading setup…</p>}>
              {direct ? (
                <DirectGitHub drive={drive} />
              ) : (
                <ConnectLocalThought drive={drive} platform={platform} />
              )}
              {platform === 'github-issues' && !direct && (
                <Button subtle onClick={() => setDirect(true)}>
                  Use a direct GitHub token instead
                </Button>
              )}
            </Suspense>
          )}
        </Dialog.Content>
      </Dialog>
    </Card>
  );
}
