import { IntegrationActions } from './IntegrationActions';
import type { IntegrationEvent } from './integrationAutomation';
import { SyncRecovery } from './SyncRecovery';
import { useEffect, useState } from 'react';
import {
  findSchema,
  pluginSchema,
  previewPluginSync,
  applyPluginSync,
  getPluginSync,
  pluginSyncSchedule,
  type PluginSyncSchedule,
  useStore,
  type PluginSyncSession,
  type JSONValue,
} from '@tomic/react';
import { Button } from '@components/Button';
import { Column, Row } from '@components/Row';
import { Card } from '@components/Card';

export interface ConnectionDefinition {
  release: string;
  config: JSONValue;
  events: IntegrationEvent[];
  warnings?: string[];
  labels?: Record<string, string>;
}
export function useIntegrationConnection(plugin: string, drive: string) {
  const store = useStore();
  const [definition, setDefinition] = useState<ConnectionDefinition | null>();
  useEffect(() => {
    let active = true;

    const load = async () => {
      const schema = await findSchema(store, drive, pluginSchema());
      const resource = await store.getResource(plugin);
      const property = schema.properties?.['plugin-connection'];
      const raw = property ? resource.get(property) : undefined;
      const value = typeof raw === 'string' ? JSON.parse(raw) : raw;
      if (active)
        setDefinition(
          value && typeof value === 'object'
            ? (value as unknown as ConnectionDefinition)
            : null,
        );
    };

    void load().catch(() => {
      if (active) setDefinition(null);
    });
    const unsubscribe = store.subscribe(plugin, () => void load());

    return () => {
      active = false;
      unsubscribe();
    };
  }, [store, plugin, drive]);

  return definition;
}
export function IntegrationConnection({
  plugin,
  drive,
  definition,
}: {
  plugin: string;
  drive: string;
  definition: ConnectionDefinition;
}): React.JSX.Element {
  const store = useStore();
  const [session, setSession] = useState<PluginSyncSession | null>();
  const [pending, setPending] = useState<'preview' | 'apply' | 'schedule'>();
  const busy = pending !== undefined;
  const [schedule, setSchedule] = useState<PluginSyncSchedule | null>();
  const [error, setError] = useState<string>();
  const target = { drive, plugin };
  useEffect(() => {
    let active = true;

    const load = async () => {
      try {
        const [s, background] = await Promise.all([
          getPluginSync(store, { drive, plugin }),
          pluginSyncSchedule(store, { drive, plugin, run: '' }),
        ]);

        if (active) {
          setSession(s);
          setSchedule(background);
        }
      } catch (e) {
        if (active) setError(String(e));
      }
    };

    void load();
    const timer = setInterval(load, 2000);

    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [store, drive, plugin]);

  const perform = async (approve: boolean) => {
    setPending(approve ? 'apply' : 'preview');
    setError(undefined);

    try {
      if (!approve)
        setSession(
          await previewPluginSync(store, {
            ...target,
            release: definition.release,
            config: definition.config,
          }),
        );
      else if (session) {
        setSession(
          await applyPluginSync(store, { ...target, run: session.run }),
        );
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setPending(undefined);
    }
  };

  const setBackground = async (enabled: boolean) => {
    if (!session) return;
    setPending('schedule');

    try {
      setSchedule(
        await pluginSyncSchedule(store, {
          ...target,
          run: session.run,
          interval_seconds: enabled ? 60 : 0,
        }),
      );
      setError(undefined);
    } catch (e) {
      setError(String(e));
    } finally {
      setPending(undefined);
    }
  };

  const unfinished = session?.approved_by && session.status !== 'complete';
  const changes = (
    session?.proposal as
      | {
          changes?: Array<{
            number?: number;
            id?: string;
            kind?: string;
            desired: Record<string, unknown>;
          }>;
        }
      | undefined
  )?.changes;

  return (
    <Column gap='1rem'>
      <h2>Sync</h2>
      <CompatibilityNotes warnings={definition.warnings} />
      <Row gap='0.5rem'>
        <Button
          loading={pending === 'preview' ? 'Preparing preview…' : undefined}
          disabled={busy || !!unfinished}
          onClick={() => perform(false)}
        >
          Preview sync
        </Button>
        {session &&
          session.status !== 'complete' &&
          session.status !== 'running' && (
            <Button
              disabled={
                busy || session.problems.some(p => p.severity === 'error')
              }
              loading={pending === 'apply' ? 'Applying sync…' : undefined}
              onClick={() => perform(true)}
            >
              {unfinished ? 'Resume sync' : 'Approve sync'}
            </Button>
          )}
      </Row>
      {pending === 'preview' && (
        <p role='status'>Checking for changes. This may take a moment.</p>
      )}
      {session?.status === 'running' && (
        <p>Sync continues on the server. You can close this page.</p>
      )}
      <Row gap='0.5rem'>
        <Button
          disabled={busy || (!schedule && session?.status !== 'complete')}
          loading={pending === 'schedule' ? 'Saving…' : undefined}
          onClick={() => setBackground(!schedule)}
        >
          {schedule ? 'Pause background sync' : 'Enable background sync'}
        </Button>
        {schedule && <p>Checks every minute, even with the browser closed.</p>}
      </Row>
      {schedule?.error && <Card role='alert'>{schedule.error}</Card>}
      {(error || session?.error) && (
        <Card role='alert'>{error || session?.error}</Card>
      )}
      {session && (
        <SyncRecovery
          drive={drive}
          plugin={plugin}
          session={session}
          onResolved={() => void perform(true)}
        />
      )}
      {session?.status === 'complete' && <p>Sync complete.</p>}
      {session?.problems.map((p, i) => (
        <p key={i} role='alert'>
          {p.message}
        </p>
      ))}
      {changes && (
        <details open={session?.status === 'preview'}>
          <summary>{changes.length} records</summary>
          <Column gap='0.5rem'>
            {changes.map((change, i) => (
              <Card key={i}>
                <strong>
                  {change.kind || 'record'} ·{' '}
                  {change.id || change.number || i + 1}
                </strong>
                <dl>
                  {Object.entries(change.desired).map(([key, value]) => (
                    <div key={key}>
                      <dt>{definition.labels?.[key] || key}</dt>
                      <dd
                        style={{
                          whiteSpace: 'pre-wrap',
                          overflowWrap: 'anywhere',
                        }}
                      >
                        {typeof value === 'string'
                          ? value
                          : JSON.stringify(value)}
                      </dd>
                    </div>
                  ))}
                </dl>
              </Card>
            ))}
          </Column>
        </details>
      )}
      <details>
        <summary>Advanced: one-off actions and permissions</summary>
        <IntegrationActions drive={drive} plugin={plugin} />
      </details>
    </Column>
  );
}

function CompatibilityNotes({ warnings }: { warnings?: string[] }) {
  if (!warnings?.length) return null;

  return (
    <details open>
      <summary>Compatibility notes</summary>
      <ul>
        {warnings.map((warning, i) => (
          <li key={i}>{warning}</li>
        ))}
      </ul>
    </details>
  );
}
