import { useIntegrationProxy } from '@helpers/integrationProxy';
import { useEffect, useState, useRef, Suspense } from 'react';
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

export function LocalThoughtCatalog({
  drive,
  search,
}: {
  drive?: string;
  search: string;
}) {
  const store = useStore();
  const origin = useIntegrationProxy();
  const [platforms, setPlatforms] = useState<string[]>();
  const [error, setError] = useState('');
  const [returned, setReturned] = useState<string>();
  const completing = useRef(false);
  useEffect(() => {
    const controller = new AbortController();
    setPlatforms(undefined);
    setError('');
    browserIntegrations(origin)
      .catalog(controller.signal)
      .then(data => {
        if (!controller.signal.aborted) setPlatforms(data);
      })
      .catch(reason => {
        if (!controller.signal.aborted) setError(String(reason));
      });

    return () => controller.abort();
  }, [origin]);
  // Removing callback parameters can remount this route before redemption
  // finishes. A short-lived marker lets the current mount resume setup.
  useEffect(() => {
    const restore = () => {
      try {
        const completed = JSON.parse(
          sessionStorage.getItem('localthought-completed') || 'null',
        );

        if (
          completed?.drive === drive &&
          completed.actor === store.getAgent()?.subject &&
          completed.origin === origin &&
          completed.expires > Date.now()
        ) {
          setReturned(completed.platform);
        } else {
          setReturned(undefined);
        }
      } catch {
        /* Ignore an invalid completion marker. */
      }
    };

    restore();
    window.addEventListener('localthought-connected', restore);

    return () => window.removeEventListener('localthought-connected', restore);
  }, [store, drive, origin]);
  useEffect(() => {
    if (!drive || completing.current) return;
    const url = new URL(location.href);
    const state = url.searchParams.get('integration_state');
    const code = url.searchParams.get('connection_code');
    const callbackPlatform = url.searchParams.get('platform');
    const callbackError = url.searchParams.get('error');
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
        pending.platform !== callbackPlatform ||
        (!code && callbackError !== 'access_denied') ||
        (code && callbackError)
      )
        throw new Error(
          'Connection return is missing, expired or belongs to another account. Start connecting again.',
        );
      // A redeem response can be lost after the one-time code is consumed.
      sessionStorage.removeItem('localthought-pending');

      if (callbackError) {
        browserIntegrations(pending.origin ?? origin).cancel(
          drive,
          actor!,
          state,
        );
        throw new Error(
          'The connection was not authorized. Start connecting again when you are ready.',
        );
      }

      const result = await proxyRequest<{
        connection: string;
        platform: string;
      }>(store, 'finish', {
        drive,
        state,
        connectionCode: code!,
        origin: pending.origin ?? origin,
      });
      if (result.platform !== pending.platform)
        throw new Error(
          'Returned platform did not match the requested platform',
        );
      localStorage.setItem(
        connectionKey(drive, actor!, result.platform, pending.origin ?? origin),
        JSON.stringify({
          ...result,
          drive,
          actor,
        }),
      );
      sessionStorage.setItem(
        'localthought-completed',
        JSON.stringify({
          drive,
          actor,
          platform: result.platform,
          origin: pending.origin ?? origin,
          expires: Date.now() + 600000,
        }),
      );
      window.dispatchEvent(new Event('localthought-connected'));
      setReturned(result.platform);
    };

    void finish().catch(reason => setError(String(reason)));
  }, [drive, store, origin]);
  const visible = platforms?.filter(id =>
    `${id} ${platformName(id)}`.toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <>
      {error && <ErrMessage role='alert'>{error}</ErrMessage>}
      {!platforms && !error && <p>Loading LocalThought platforms…</p>}
      {visible?.map(platform => (
        <PlatformCard
          key={`${origin}:${platform}:${returned}`}
          platform={platform}
          origin={origin}
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
  origin,
}: {
  platform: string;
  drive?: string;
  returned: boolean;
  origin: string;
}) {
  const [dialog, show, , isOpen] = useDialog({
    onCancel: () => {
      if (returned) sessionStorage.removeItem('localthought-completed');
    },
  });
  useEffect(() => {
    if (returned) show();
  }, [returned, show]);

  return (
    <Card
      highlight
      data-integration={`proxy:${platform}`}
      data-integration-source='proxy'
    >
      <Column gap='0.75rem'>
        <h2>{platformName(platform)}</h2>
        <small>Via integration proxy</small>
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
              <ConnectLocalThought
                drive={drive}
                platform={platform}
                origin={origin}
              />
            </Suspense>
          )}
        </Dialog.Content>
      </Dialog>
    </Card>
  );
}
