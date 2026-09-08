import { useCallback, useEffect, useState } from 'react';
import {
  useStore,
  ensureSchema,
  pluginSchema,
  timeTrackingSchema,
  core,
  pinPluginRelease,
  executeServerPlugin,
  signRequest,
  type Resource,
} from '@tomic/react';
import { Button } from '@components/Button';
import { Column, Row } from '@components/Row';
import Field from '@components/forms/Field';
import { Input, ErrMessage } from '@components/forms/InputStyles';
import { BasicSelect } from '@components/forms/BasicSelect';
import { useNavigateWithTransition } from '@hooks/useNavigateWithTransition';
import { constructOpenURL } from '@helpers/navigation';
import {
  timeTrackerTables,
  type TimeTableTarget,
} from '../../../../../integrations/clockify/atomic';
import { useAddToOntology } from '@hooks/useAddToOntology';
import {
  buildTableFromSpec,
  type BuildTableResult,
} from '@chunks/TablePage/createTableFromSpec';
import { TABLE_TEMPLATES } from '@chunks/TablePage/tableTemplates';
import { RunPluginDialog } from './RunPluginDialog';
import { createPlugin, setPluginSource } from './runScript';
import {
  manifest,
  origin,
  type Config,
} from '../../../../../integrations/clockify/model';
import source from '../../../../../integrations/clockify/plugin.js?raw';

export function ConnectClockify({ drive }: { drive: string }) {
  const store = useStore();
  const addToOntology = useAddToOntology();
  const [tables, setTables] = useState<TimeTableTarget[]>([]);
  const [target, setTarget] = useState('');
  const [destination, setDestination] = useState<string>();
  const [reviewed, setReviewed] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    let active = true;
    void timeTrackerTables(store, drive)
      .then(items => {
        if (active) setTables(items);
      })
      .catch(e => {
        if (active) setError(String(e));
      });

    return () => {
      active = false;
    };
  }, [store, drive]);
  const [key, setKey] = useState('');
  const [plugin, setPlugin] = useState<string>();
  const draftId = `installation:clockify:draft:${store.getAgent()?.subject}`;
  useEffect(() => {
    let active = true;
    void store
      .findByLocalId(drive, drive, draftId)
      .then(resource => {
        if (active && resource) setPlugin(resource.subject);
      })
      .catch(e => {
        if (active) setError(String(e));
      });

    return () => {
      active = false;
    };
  }, [store, drive, draftId]);
  const [user, setUser] = useState<{ id: string; name: string }>();
  const [workspaces, setWorkspaces] = useState<
    Array<{ id: string; name: string }>
  >([]);
  const [workspace, setWorkspace] = useState('');
  const [days, setDays] = useState('7');
  const [busy, setBusy] = useState(false);
  const [table, setTable] = useState<BuildTableResult>();
  const [preview, setPreview] = useState<Resource>();
  const onPreviewChange = useCallback((open: boolean) => {
    if (!open) setPreview(undefined);
  }, []);

  const connect = async () => {
    if (busy) return;

    if (!key.trim() && !plugin) {
      setError('Enter your Clockify API key.');

      return;
    }

    setBusy(true);
    setError('');

    try {
      const subject =
        plugin ??
        (await createPlugin(
          store,
          { drive, parent: drive, localId: draftId },
          'Clockify import',
          /* @wc-ignore */ `${source}\nexport const manifest=${JSON.stringify(manifest())};`,
        ));
      setPlugin(subject);

      if (key.trim()) {
        const url = `${store.getServerUrl()}/plugin-secret`;
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            ...(await signRequest(url, store.getAgent()!, {})),
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            drive,
            plugin: subject,
            name: 'clockify',
            value: key.trim(),
            origins: [origin],
          }),
        });
        if (!response.ok)
          throw new Error(
            'Could not save the Clockify key on your server. Try again.',
          );
      }

      await pinPluginRelease(store, { drive, plugin: subject });
      const result = await executeServerPlugin(store, {
        drive,
        plugin: subject,
        source: /* @wc-ignore */ `${source}\nexport const manifest=${JSON.stringify(manifest())};`,
        input: {
          phase: 'discover',
          trigger: { kind: 'manual', at: Date.now() },
        },
      });
      if (result.error || !result.verdict)
        throw new Error(
          result.error ?? 'Clockify discovery produced no result.',
        );
      const { discovery } = JSON.parse(result.verdict);
      if (!discovery?.user || !Array.isArray(discovery.workspaces))
        throw new Error('Clockify discovery returned an invalid result.');
      const account = discovery.user;
      const spaces = discovery.workspaces;
      setUser(account);
      setWorkspaces(spaces);
      setWorkspace(spaces[0]?.id ?? '');
      setKey('');
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const setup = async () => {
    if (busy || !plugin || !user || !workspace) return;
    setBusy(true);
    setError('');

    try {
      const existing = target
        ? (await timeTrackerTables(store, drive)).find(
            t => t.tableSubject === target,
          )
        : undefined;
      if (target && !existing)
        throw new Error(
          'That table is no longer compatible. Choose another Time Tracker table.',
        );
      const terms =
        existing?.schema ??
        (await ensureSchema(store, drive, timeTrackingSchema()));
      const template = TABLE_TEMPLATES.find(t => t.id === 'time-tracker')!;
      const targetTable =
        existing ??
        table ??
        (await buildTableFromSpec(
          store,
          {
            ...template.spec!,
            name: 'Clockify time entries',
            rowName: template.rowName,
          },
          {
            parent: plugin,
            driveSubject: drive,
            addToOntology,
            installationKey: `${plugin}:clockify-table`,
          },
        ));
      if (!existing) setTable(targetTable as BuildTableResult);
      const config: Config = {
        drive,
        container: plugin,
        workspace,
        user: user.id,
        userName: user.name,
        lookbackDays: Number(days),
        table: targetTable.tableSubject,
        rowClass: targetTable.classSubject,
        projectClass: terms.classes['work-project'],
        personClass: terms.classes['work-person'],
        properties: {
          start: terms.properties['work-start'],
          end: terms.properties['work-end'],
          project: terms.properties['work-project'],
          person: terms.properties['work-person'],
          billable: terms.properties['work-billable'],
          identity: terms.properties['work-source-id'],
        },
      };
      await setPluginSource(
        store,
        plugin,
        drive,
        /* @wc-ignore */ `${source}\nconst settings=${JSON.stringify(config)};\nexport const manifest=${JSON.stringify(manifest(workspace, user.id))};`,
      );
      const resource = await store.getResource(plugin);
      await resource.set(
        core.properties.name,
        `Clockify: ${workspaces.find(w => w.id === workspace)?.name}`,
      );
      await resource.set('https://atomicdata.dev/properties/emoji', '⏱️');
      const schema = await ensureSchema(store, drive, pluginSchema());
      await resource.set(schema.properties['plugin-schemas'], {
        table: targetTable.tableSubject,
      });
      await resource.save();
      await pinPluginRelease(store, { drive, plugin });

      if (resource.get(core.properties.localId) === draftId) {
        resource.remove(core.properties.localId);
        await resource.save();
      }

      setDestination(targetTable.tableSubject);
      setPreview(resource);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Column gap='1rem'>
      <p>
        Bring your completed entries into the Time Tracker template, linked to
        projects and the person who logged them. Review every proposed import
        first.
      </p>
      {!user ? (
        <form
          onSubmit={e => {
            e.preventDefault();
            void connect();
          }}
        >
          <Column gap='0.75rem'>
            <Field fieldId='clockify-key' label='Clockify API key'>
              <Input
                id='clockify-key'
                type='password'
                autoComplete='off'
                value={key}
                disabled={busy}
                onChange={e => setKey(e.target.value)}
              />
            </Field>
            <p>
              Find your API key in Clockify profile settings. It is stored on
              your AtomicServer and only used for read requests.
            </p>
            <Button disabled={busy} type='submit'>
              {busy ? 'Connecting…' : 'Find my workspaces'}
            </Button>
          </Column>
        </form>
      ) : (
        <Column>
          <Field fieldId='clockify-workspace' label='Workspace'>
            <BasicSelect
              id='clockify-workspace'
              value={workspace}
              disabled={busy || reviewed}
              onChange={e => setWorkspace(e.target.value)}
            >
              {workspaces.map(w => (
                <option key={w.id} value={w.id}>
                  {w.name}
                </option>
              ))}
            </BasicSelect>
          </Field>
          <Field fieldId='clockify-table' label='Import into'>
            <BasicSelect
              id='clockify-table'
              value={target}
              disabled={busy || reviewed}
              onChange={e => setTarget(e.target.value)}
            >
              <option value=''>New Time Tracker table</option>
              {tables.map(t => (
                <option key={t.tableSubject} value={t.tableSubject}>
                  {t.name}
                </option>
              ))}
            </BasicSelect>
          </Field>
          <Field fieldId='clockify-range' label='Import my completed entries'>
            <BasicSelect
              id='clockify-range'
              value={days}
              disabled={busy}
              onChange={e => setDays(e.target.value)}
            >
              <option value='7'>Past 7 days</option>
              <option value='30'>Past 30 days</option>
            </BasicSelect>
          </Field>
          <ClockifyImportHelp />
          {!workspaces.length && (
            <p>No Clockify workspaces are available for this account.</p>
          )}
          <Button disabled={busy || !workspace} onClick={setup}>
            {busy ? 'Preparing preview…' : 'Preview import'}
          </Button>
        </Column>
      )}
      {destination && plugin && (
        <ClockifyImportLinks table={destination} plugin={plugin} />
      )}
      <Column aria-live='polite'>
        {error && <ErrMessage role='alert'>{error}</ErrMessage>}
      </Column>
      {preview && (
        <RunPluginDialog
          resource={preview}
          drive={drive}
          show
          onShowChange={onPreviewChange}
          onReviewed={() => setReviewed(true)}
        />
      )}
    </Column>
  );
}

// Keep these messages outside guarded JSX so extraction retains every sibling.
function ClockifyImportHelp() {
  return (
    <Column>
      <p>
        Compatible Time Tracker tables appear here. Their views and existing
        entries are kept.
      </p>
      <p>
        Each run imports your entries from the selected number of days before
        that run. Running timers and breaks are skipped. Repeating the import
        updates changed source fields, preserves local edits and asks you to
        resolve conflicts. It never deletes entries.
      </p>
    </Column>
  );
}

function ClockifyImportLinks({
  table,
  plugin,
}: {
  table: string;
  plugin: string;
}) {
  const navigate = useNavigateWithTransition();

  return (
    <Column>
      <p>
        Your import setup is saved. Open the table, or manage this import to
        review future runs and its schedule.
      </p>
      <Row wrapItems>
        <Button onClick={() => navigate(constructOpenURL(table))}>
          Open time entries
        </Button>
        <Button subtle onClick={() => navigate(constructOpenURL(plugin))}>
          Manage import
        </Button>
      </Row>
    </Column>
  );
}
