import { useEffect, useState } from 'react';
import {
  core,
  dataBrowser,
  ensureSchema,
  executeServerPlugin,
  useStore,
  type Resource,
} from '@tomic/react';
import { Button } from '@components/Button';
import { Column } from '@components/Row';
import Field from '@components/forms/Field';
import { Input, ErrMessage } from '@components/forms/InputStyles';
import { AtomicLink } from '@components/AtomicLink';
import { pluginClassesFor } from './runScript';
import { ensureInstallationResource } from './installationResources';
import { RunPluginDialog } from './RunPluginDialog';
import {
  connectionKey,
  platformName,
  proxyRequest,
  type SavedConnection,
} from './localThought';
import {
  platformSchema,
  termKey,
  type FetchedPlatform,
} from '../../../../../integrations/localthought/schema';
import type { Config } from '../../../../../integrations/localthought/plugin';
import source from '../../../../../integrations/localthought/plugin.js?raw';

export function ConnectLocalThought({
  drive,
  platform,
}: {
  drive: string;
  platform: string;
}) {
  const store = useStore();
  const actor = store.getAgent()?.subject ?? '';
  const [connection] = useState<SavedConnection | undefined>(() => {
    const raw = localStorage.getItem(connectionKey(drive, actor, platform));
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
  const [calendarRange, setCalendarRange] = useState(() => ({
    start: new Date().toISOString().slice(0, 10),
    end: new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10),
  }));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [preview, setPreview] = useState<{
    resource: Resource;
    verdict: string;
    tables: string[];
  }>();
  const [tables, setTables] = useState<string[]>([]);
  useEffect(() => {
    const controller = new AbortController();
    fetch(
      `${store.getServerUrl()}/integration-proxy/platform?platform=${encodeURIComponent(platform)}`,
      { signal: controller.signal },
    )
      .then(async response => {
        if (!response.ok) throw new Error(await response.text());
        const data = await response.json();
        setParameters(data.parameters);
        setCollections(data.collections);
        setConstants(
          Object.fromEntries(
            data.parameters.map((key: string) => [
              key,
              (
                {
                  owner: 'ontola',
                  repo: 'atomic-server',
                  calendarId: 'primary',
                } as Record<string, string>
              )[key] ?? '',
            ]),
          ),
        );
      })
      .catch(reason => {
        if (!controller.signal.aborted) setError(String(reason));
      });
    return () => controller.abort();
  }, [store, platform]);
  const connect = async () => {
    setBusy(true);
    setError('');
    try {
      const result = await proxyRequest<{ url: string; state: string }>(
        store,
        'start',
        { drive, platform, returnUrl: `${location.origin}/app/integrations` },
      );
      sessionStorage.setItem(
        'localthought-pending',
        JSON.stringify({ state: result.state, drive, actor, platform }),
      );
      location.assign(result.url);
    } catch (reason) {
      setError(String(reason));
      setBusy(false);
    }
  };
  const fetchRecords = async () => {
    if (!connection || busy) return;
    setBusy(true);
    setError('');
    try {
      const fetched = await proxyRequest<FetchedPlatform>(store, 'fetch', {
        drive,
        connection: connection.connection,
        constants,
        ...(platform === 'google-calendar' ? { calendarRange } : {}),
      });
      if (fetched.platform !== platform)
        throw new Error('Imported platform did not match this connection');
      const terms = await pluginClassesFor(store, drive);
      const name = platformName(platform);
      const identity = `localthought:${connection.connection}:${JSON.stringify(Object.entries(constants).sort())}`;
      const resource = await ensureInstallationResource(store, drive, {
        parent: drive,
        localId: identity,
        isA: [terms.classes['plugin-script']],
        propVals: {
          [core.properties.name]: name,
          [terms.properties['plugin-source']]: source,
          [terms.properties.trigger]: 'manual',
        },
      });
      const schema = await ensureSchema(
        store,
        drive,
        platformSchema(platform, fetched.ontology.terms),
      );
      const destinations: Config['destinations'] = {};
      const properties: Record<string, string> = {};
      for (const term of fetched.ontology.terms.filter(
        t => t.kind === 'property',
      ))
        properties[term.shortname] = schema.properties[termKey(platform, term)];
      const classes = fetched.ontology.terms.filter(t => t.kind === 'class');
      for (const term of classes) {
        const rowClass = schema.classes[termKey(platform, term)];
        const tableName =
          classes.length === 1 ? name : `${name}: ${term.shortname}`;
        const destination = await ensureInstallationResource(store, drive, {
          parent: resource.subject,
          localId: `${identity}:table:${term.shortname}`,
          isA: [dataBrowser.classes.table],
          propVals: {
            [core.properties.name]: tableName,
            [core.properties.classtype]: rowClass,
          },
        });
        const columns = [
          core.properties.name,
          ...[...term.requires, ...term.recommends]
            .map(path => fetched.ontology.terms.find(t => t.path === path))
            .filter(t => t !== undefined)
            .map(t => properties[t.shortname]),
        ];
        const view = await ensureInstallationResource(store, drive, {
          parent: destination.subject,
          localId: `${identity}:view:${term.shortname}`,
          isA: [dataBrowser.classes.view],
          propVals: {
            [core.properties.name]: tableName,
            [dataBrowser.properties.viewKind]: 'table',
            [dataBrowser.properties.viewColumns]: columns,
          },
        });
        await destination.set(dataBrowser.properties.tableViews, [
          view.subject,
        ]);
        await destination.set(
          dataBrowser.properties.tableDefaultView,
          view.subject,
        );
        await destination.save();
        destinations[term.shortname] = { table: destination.subject, rowClass };
      }
      const config = { platform, destinations, properties };
      await resource.set(terms.properties['plugin-schemas'], {
        localthought: { ...config, connection: connection.connection },
      });
      await resource.save();
      const result = await executeServerPlugin(store, {
        drive,
        plugin: resource.subject,
        source,
        input: {
          config: { ...config, records: fetched.records },
          trigger: {
            kind: 'manual',
            at: Date.now(),
            subject: resource.subject,
          },
        },
      });
      if (result.error || !result.verdict)
        throw new Error(result.error ?? 'Import returned no preview');
      setPreview({
        resource,
        verdict: result.verdict,
        tables: Object.values(destinations).map(d => d.table),
      });
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
        preview an import.
      </p>
      <Button disabled={busy} onClick={connect}>
        {connection ? 'Reconnect account' : 'Install and connect'}
      </Button>
      {connection && (
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
          {platform === 'google-calendar' && (
            <>
              <Field fieldId='calendar-start' label='Events from (UTC)'>
                <Input
                  id='calendar-start'
                  type='date'
                  value={calendarRange.start}
                  disabled={busy}
                  onChange={e =>
                    setCalendarRange({
                      ...calendarRange,
                      start: e.target.value,
                    })
                  }
                />
              </Field>
              <Field fieldId='calendar-end' label='Events before (UTC)'>
                <Input
                  id='calendar-end'
                  type='date'
                  value={calendarRange.end}
                  disabled={busy}
                  onChange={e =>
                    setCalendarRange({ ...calendarRange, end: e.target.value })
                  }
                />
              </Field>
            </>
          )}
          <p>{collections.join(', ')}</p>
          <ImportScopeHelp />
          <Button
            disabled={
              busy || !collections.length || parameters.some(p => !constants[p])
            }
            onClick={fetchRecords}
          >
            {busy ? 'Fetching…' : 'Fetch and preview'}
          </Button>
        </>
      )}
      {error && <ErrMessage role='alert'>{error}</ErrMessage>}
      {tables.map(table => (
        <AtomicLink key={table} subject={table}>
          Open imported records
        </AtomicLink>
      ))}
      {preview && (
        <RunPluginDialog
          resource={preview.resource}
          drive={drive}
          show
          verdict={preview.verdict}
          triggerKind='manual'
          onShowChange={open => {
            if (!open) setPreview(undefined);
          }}
          onReviewed={() => {
            setTables(preview.tables);
            setPreview(undefined);
          }}
        />
      )}
    </Column>
  );
}

function ImportScopeHelp() {
  return (
    <p>
      Imports the collections described by the platform, following pagination.
      Review changes before applying them. No background sync or provider
      writes.
    </p>
  );
}
