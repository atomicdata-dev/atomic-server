import { useEffect, useState } from 'react';
import {
  workspaceConnections,
  findSchema,
  pluginSchema,
  readConnectionSubjects,
  useStore,
  type WorkspaceConnection,
} from '@tomic/react';
import { useSettings } from '@helpers/AppSettings';
import { Dialog, useDialog } from '@components/Dialog';
import { Button } from '@components/Button';
import { AtomicLink } from '@components/AtomicLink';
import { Row, Column } from '@components/Row';
import { ResourceInline } from '../../views/ResourceInline/ResourceInline';
import { NewAutomation } from './NewAutomation';
import { paths } from '../../routes/paths';

/** Workspace chrome; opening it never installs code, writes data or starts sync. */
export function WorkspaceControls({ workspace }: { workspace: string }) {
  const store = useStore();
  const { drive } = useSettings();
  const [dialog, show, close, isOpen] = useDialog();
  const [section, setSection] = useState<'connections' | 'automations'>(
    'connections',
  );
  const [connections, setConnections] = useState<WorkspaceConnection[]>([]);
  const [automations, setAutomations] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    if (!isOpen || !drive) return;
    let active = true;
    setLoading(true);
    setError('');

    const load = async () => {
      const linked = await workspaceConnections(store, drive, workspace);
      const schema = await findSchema(store, drive, pluginSchema());
      const property = schema.properties?.['automation-integrations'];
      const ids = new Set<string>();

      if (section === 'automations' && property) {
        for (const connection of linked) {
          for (const id of await readConnectionSubjects(
            store,
            drive,
            property,
            connection.subject,
          ))
            ids.add(id);
        }

        // Automations without a connection can explicitly belong to this workspace.
        const association = schema.properties?.['plugin-workspace'];

        if (association) {
          for (const id of await readConnectionSubjects(
            store,
            drive,
            association,
            workspace,
          )) {
            const resource = await store.getResource(id);
            if (resource.error) throw resource.error;
            if (resource.get(property)) ids.add(id);
          }
        }
      }

      if (active) {
        setConnections(linked);
        setAutomations([...ids]);
      }
    };

    void load()
      .catch(e => {
        if (active) setError(String(e));
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [store, drive, workspace, isOpen, section, refresh]);
  if (!drive) return null;

  return (
    <>
      <Row gap='0.5rem'>
        <Button
          subtle
          onClick={() => {
            setSection('connections');
            show();
          }}
        >
          Connections
        </Button>
        <Button
          subtle
          onClick={() => {
            setSection('automations');
            show();
          }}
        >
          Automations
        </Button>
      </Row>
      <Dialog {...dialog} width='36rem'>
        <Dialog.Title>
          {section === 'connections' ? 'Connections' : 'Automations'}
        </Dialog.Title>
        <Dialog.Content>
          <Column gap='1rem'>
            {loading ? (
              <p role='status'>Loading workspace…</p>
            ) : error ? (
              <>
                <p role='alert'>{error}</p>
                <Button onClick={() => setRefresh(v => v + 1)}>
                  Try again
                </Button>
              </>
            ) : section === 'connections' ? (
              <>
                <p>
                  Connect services to this workspace. Your data and views stay
                  here when sync is paused.
                </p>
                {connections.length === 0 && <p>No connections yet.</p>}
                {connections.map(connection => (
                  <Row key={connection.subject} justify='space-between'>
                    <span>{connection.name}</span>
                    <AtomicLink subject={connection.subject}>
                      Connection settings
                    </AtomicLink>
                  </Row>
                ))}
                <AtomicLink
                  path={`${paths.integrations}?workspace=${encodeURIComponent(workspace)}`}
                >
                  Connect a service
                </AtomicLink>
              </>
            ) : (
              <>
                <p>
                  Automations act on your data and can use connected services.
                  Sync works independently.
                </p>
                {automations.map(subject => (
                  <ResourceInline key={subject} subject={subject} />
                ))}
                {automations.length === 0 && <p>No automations yet.</p>}
              </>
            )}
          </Column>
        </Dialog.Content>
        {section === 'automations' && !loading && !error && (
          <Dialog.Actions>
            <NewAutomation
              drive={drive}
              connections={connections.map(c => c.subject)}
              workspace={workspace}
              onStart={() => close()}
            />
          </Dialog.Actions>
        )}
      </Dialog>
    </>
  );
}
