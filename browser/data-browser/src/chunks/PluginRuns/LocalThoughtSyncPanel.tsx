import { useEffect, useState } from 'react';
import { core, useStore, type Resource, type JSONValue } from '@tomic/react';
import { googleCalendarIntegration } from '@localthought/atomic-integrations/ui/GoogleCalendar';
import { Column, Row } from '@components/Row';
import { Button } from '@components/Button';
import { ErrMessage } from '@components/forms/InputStyles';
import { AtomicLink } from '@components/AtomicLink';
import { browserIntegrations } from './localThought';
import { localImportRows } from './localImportVerdict';
import {
  findInstallation,
  refreshLocalThought,
  REFRESH_INTERVAL,
  SYNC_CHANGED,
  type LocalThoughtInstallation,
} from './localThoughtSync';

/** Visiting the installed folder or its tables resumes this browser's import. */
export function LocalThoughtSync({ resource }: { resource: Resource }) {
  const store = useStore();
  const subject = resource.subject;
  const parent = resource.get(core.properties.parent) as string | undefined;
  const actor = store.getAgent()?.subject;
  const drive = store.getDrive();
  const [installation, setInstallation] = useState<LocalThoughtInstallation>();

  useEffect(() => {
    const update = () =>
      setInstallation(findInstallation(store, subject, parent));

    const refresh = () => {
      const entry = findInstallation(store, subject, parent);

      if (entry && navigator.onLine && document.visibilityState === 'visible') {
        void refreshLocalThought(store, entry);
      }

      update();
    };

    window.addEventListener(SYNC_CHANGED, update);
    window.addEventListener('storage', update);
    window.addEventListener('online', refresh);
    document.addEventListener('visibilitychange', refresh);
    refresh();
    const timer = window.setInterval(refresh, REFRESH_INTERVAL);

    return () => {
      clearInterval(timer);
      window.removeEventListener(SYNC_CHANGED, update);
      window.removeEventListener('storage', update);
      window.removeEventListener('online', refresh);
      document.removeEventListener('visibilitychange', refresh);
    };
  }, [store, subject, parent, actor, drive]);

  if (
    !installation ||
    installation.actor !== actor ||
    installation.drive !== drive
  )
    return null;
  const { config } = installation;
  const Sync = [googleCalendarIntegration].find(
    item => item.id === installation.platform,
  )?.Sync;

  return (
    <Column gap='0.5rem'>
      <Row gap='0.75rem' center>
        <span role='status'>
          {installation.syncing
            ? 'Syncing…'
            : installation.error
              ? 'Sync needs attention'
              : installation.lastSuccess
                ? `Last synced ${new Date(installation.lastSuccess).toLocaleString()}`
                : 'Waiting to sync'}
        </span>
        <Button
          subtle
          disabled={installation.syncing}
          onClick={() => void refreshLocalThought(store, installation)}
        >
          Sync now
        </Button>
        {subject !== installation.folder && (
          <AtomicLink subject={installation.folder}>Open folder</AtomicLink>
        )}
      </Row>
      <small>Refreshes every five minutes while open in this browser.</small>
      {installation.error && (
        <ErrMessage role='alert'>{installation.error}</ErrMessage>
      )}
      {Sync && config && (
        <Sync
          config={config}
          disabled={!!installation.syncing}
          rows={() => localImportRows(store, installation.drive, config)}
          request={(path, init) =>
            browserIntegrations(installation.origin).request(
              installation.drive,
              installation.actor,
              installation.connection,
              installation.platform,
              path,
              init,
            )
          }
          checkpoint={async (rowSubject, values) => {
            const row = await store.getResource(rowSubject);
            for (const [property, value] of Object.entries(values))
              await row.set(property, value as JSONValue);
            await row.save();
          }}
        />
      )}
    </Column>
  );
}
