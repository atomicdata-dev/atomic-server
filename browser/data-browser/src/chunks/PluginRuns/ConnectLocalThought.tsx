import { getIntegrationProxy } from '@helpers/integrationProxy';
import {
  importInstallationIdentity,
  readSavedConnection,
} from '../../../../../integrations/localthought/settings';
import { googleCalendarIntegration } from '@localthought/atomic-integrations/ui/GoogleCalendar';
import { useEffect, useState } from 'react';
import { useStore } from '@tomic/react';
import { Button } from '@components/Button';
import { Column } from '@components/Row';
import Field from '@components/forms/Field';
import { Input, ErrMessage } from '@components/forms/InputStyles';
import { AtomicLink } from '@components/AtomicLink';
import {
  browserIntegrations,
  proxyRequest,
  type SavedConnection,
} from './localThought';
import { installLocalThought, refreshLocalThought } from './localThoughtSync';

export function ConnectLocalThought({
  drive,
  platform,
  origin = getIntegrationProxy(),
}: {
  drive: string;
  platform: string;
  origin?: string;
}) {
  const extension = [googleCalendarIntegration].find(
    item => item.id === platform,
  );
  const ImportControls = extension?.ImportControls;
  const store = useStore();
  const actor = store.getAgent()?.subject ?? '';
  const [connection] = useState<SavedConnection | undefined>(() => {
    const raw = readSavedConnection(
      localStorage,
      origin,
      drive,
      actor,
      platform,
    );
    if (!raw) return;

    try {
      return JSON.parse(raw);
    } catch {
      return;
    }
  });
  const [parameters, setParameters] = useState<string[]>([]);
  const [constants, setConstants] = useState<Record<string, string>>({});
  const [collections, setCollections] = useState<string[]>([]);
  const [selection, setSelection] = useState(() =>
    extension?.defaultSelection(),
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [folder, setFolder] = useState<string>();
  useEffect(() => {
    const controller = new AbortController();
    browserIntegrations(origin)
      .describe(platform)
      .then(data => {
        if (controller.signal.aborted) return;
        setParameters(data.parameters);
        setCollections(data.collections);
        setConstants(
          Object.fromEntries(
            data.parameters.map((key: string) => [
              key,
              (
                extension?.defaultConstants as
                  | Record<string, string>
                  | undefined
              )?.[key] ?? '',
            ]),
          ),
        );
      })
      .catch(reason => {
        if (!controller.signal.aborted) setError(String(reason));
      });

    return () => controller.abort();
  }, [store, platform, origin, extension?.defaultConstants]);

  const connect = async () => {
    setBusy(true);
    setError('');

    try {
      const result = await proxyRequest<{ url: string; state: string }>(
        store,
        'start',
        {
          drive,
          origin,
          platform,
          returnUrl: `${location.origin}/app/integrations`,
        },
      );
      sessionStorage.setItem(
        'localthought-pending',
        JSON.stringify({
          state: result.state,
          origin,
          drive,
          actor,
          platform,
        }),
      );
      location.assign(result.url);
    } catch (reason) {
      setError(String(reason));
      setBusy(false);
    }
  };

  const install = async () => {
    if (!connection || busy) return;
    setBusy(true);
    setError('');

    try {
      const installed = await installLocalThought(store, {
        origin,
        drive,
        actor,
        platform,
        connection: connection.connection,
        constants,
        selection:
          extension && selection ? extension.selection(selection) : undefined,
        identity: importInstallationIdentity(
          connection,
          constants,
          extension && selection ? extension.identitySuffix(selection) : '',
        ),
      });
      sessionStorage.removeItem('localthought-completed');
      setFolder(installed.folder);
      // The installation is complete. Importing continues even after this dialog closes.
      void refreshLocalThought(store, installed);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Column gap='0.75rem'>
      <p>
        Connect your personal account through LocalThought, then return here to
        choose what to sync.
      </p>
      <p>
        LocalThought will ask you to sign in and authorize this connection.
        Connection credentials stay in this browser.
      </p>
      <Button disabled={busy} onClick={connect}>
        {connection ? 'Reconnect account' : 'Install and connect'}
      </Button>
      {connection && !folder && (
        <>
          {parameters.map(parameter => (
            <Field
              key={parameter}
              fieldId={`proxy-${parameter}`}
              label={parameter}
            >
              <Input
                id={`proxy-${parameter}`}
                value={constants[parameter] ?? ''}
                onChange={e =>
                  setConstants({ ...constants, [parameter]: e.target.value })
                }
                disabled={busy}
              />
            </Field>
          ))}
          {ImportControls && selection && (
            <ImportControls
              value={selection}
              disabled={busy}
              onChange={setSelection}
            />
          )}
          <p>{collections.join(', ')}</p>
          <ImportScopeHelp writable={!!extension} />
          <Button
            disabled={
              busy || !collections.length || parameters.some(p => !constants[p])
            }
            onClick={install}
          >
            {busy ? 'Checking connection…' : 'Complete installation'}
          </Button>
        </>
      )}
      {error && <ErrMessage role='alert'>{error}</ErrMessage>}
      {folder && (
        <>
          <p>Installed. Your records are syncing in the background.</p>
          <AtomicLink subject={folder}>Open folder</AtomicLink>
        </>
      )}
    </Column>
  );
}

function ImportScopeHelp({ writable }: { writable: boolean }) {
  return (
    <p>
      Imports the collections described by the platform, following pagination.
      Syncs automatically when you open the folder and every five minutes while
      it is open. Keep this browser open to finish importing.
      {writable
        ? ' After importing, preview supported edits to send changes back.'
        : ' No provider writes.'}
    </p>
  );
}
