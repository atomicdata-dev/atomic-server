import { useEffect, useId, useState } from 'react';
import {
  executeServerPlugin,
  provisionDestination,
  pluginConfigFor,
  pluginConfigProblems,
  useStore,
  DEFAULT_ACCEPT_MAX_BYTES,
  type DeclaredAccept,
  type DeclaredDestination,
  type JSONObject,
  type PluginManifest,
  type Resource,
  type Store,
} from '@tomic/react';
import { Button } from '@components/Button';
import { Column } from '@components/Row';
import Field from '@components/forms/Field';
import { Input, ErrMessage } from '@components/forms/InputStyles';
import { AtomicLink } from '@components/AtomicLink';
import { pluginClassesFor } from './runScript';
import { RunPluginDialog } from './RunPluginDialog';

/**
 * The generic entry point for a plugin that declares `accepts`: choose a file,
 * preview what the plugin proposes for it, approve.
 *
 * The host owns acquisition: it enforces the declared size, decodes the file
 * and hands it over as `input.upload`. The plugin runs on the server (it may
 * need `ctx.query`/`ctx.read` to recognise earlier imports), and nothing is
 * written until the proposal is approved in {@link RunPluginDialog}. A plugin
 * that also declares a `destination` gets a Set up step first, which creates
 * its tables and stores them as the plugin's config.
 */
export function FileImport({
  resource,
  drive,
  source,
  manifest,
}: {
  resource: Resource;
  drive: string;
  source: string | undefined;
  manifest: PluginManifest;
}): React.JSX.Element {
  const store = useStore();
  const fileId = useId();
  const accepts = manifest.accepts ?? [];
  const [config, setConfig] = useState<JSONObject>();
  const [missing, setMissing] = useState<string[]>([]);
  const [file, setFile] = useState<File>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState<'setup' | 'preview'>();
  const [verdict, setVerdict] = useState<string>();
  const [imported, setImported] = useState(false);
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    let active = true;
    void storedConfig(store, drive, resource.subject, manifest)
      .then(found => {
        if (!active) return;
        setConfig(found);
        setMissing(
          pluginConfigProblems(found, manifest.config).map(p => p.message),
        );
      })
      .catch(reason => {
        if (active) setError(String(reason));
      });

    return () => {
      active = false;
    };
  }, [store, drive, resource.subject, manifest, refresh]);

  const setUp = async () => {
    if (!manifest.destination) return;
    setBusy('setup');
    setError('');

    try {
      await provisionDestination(
        store,
        drive,
        resource.subject,
        manifest.destination,
        manifest.config?.key,
      );
      setRefresh(n => n + 1);
    } catch (reason) {
      setError(`Could not set up this importer: ${String(reason)}`);
    } finally {
      setBusy(undefined);
    }
  };

  const preview = async () => {
    if (!file || !source || !config) return;
    setBusy('preview');
    setError('');
    setImported(false);

    try {
      const max = maxBytes(accepts);
      if (file.size > max)
        throw new Error(
          `This file is ${formatBytes(file.size)}; this importer accepts at most ${formatBytes(max)}. Export a shorter period.`,
        );
      const text = decode(await file.arrayBuffer());
      const result = await executeServerPlugin(store, {
        drive,
        plugin: resource.subject,
        source,
        input: {
          upload: {
            name: file.name,
            mediaType: file.type,
            size: file.size,
            text,
          },
          config,
          trigger: {
            kind: 'manual',
            at: Date.now(),
            subject: resource.subject,
          },
        },
      });
      if (result.error || !result.verdict)
        throw new Error(result.error ?? 'The importer returned no preview.');
      setVerdict(result.verdict);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(undefined);
    }
  };

  const table = firstTable(config);

  if (config === undefined && !error) return <p>Loading importer…</p>;

  return (
    <Column gap='0.75rem'>
      {missing.length > 0 ? (
        manifest.destination ? (
          <>
            <SetupSummary destination={manifest.destination} />
            <Button disabled={busy !== undefined} onClick={setUp}>
              {busy === 'setup' ? 'Setting up…' : 'Set up'}
            </Button>
          </>
        ) : (
          missing.map(message => <p key={message}>{message}</p>)
        )
      ) : (
        <>
          <Field fieldId={fileId} label='File to import'>
            <Input
              id={fileId}
              type='file'
              accept={acceptAttribute(accepts)}
              disabled={busy !== undefined}
              onChange={event => {
                setFile(event.target.files?.[0]);
                setError('');
                setImported(false);
              }}
            />
          </Field>
          <p>
            The file is read by this plugin on your AtomicServer, up to{' '}
            {formatBytes(maxBytes(accepts))}. Review the proposed changes before
            anything is saved.
          </p>
          <Button disabled={busy !== undefined || !file} onClick={preview}>
            {busy === 'preview' ? 'Preparing preview…' : 'Preview import'}
          </Button>
        </>
      )}
      {error && <ErrMessage role='alert'>{error}</ErrMessage>}
      {imported && table && (
        <AtomicLink subject={table}>Open imported data</AtomicLink>
      )}
      {verdict && (
        <RunPluginDialog
          resource={resource}
          drive={drive}
          show
          verdict={verdict}
          triggerKind='manual'
          onShowChange={open => {
            if (!open) setVerdict(undefined);
          }}
          onReviewed={() => {
            setImported(true);
            setVerdict(undefined);
          }}
        />
      )}
    </Column>
  );
}

/** What Set up is about to create, named the way the sidebar will show it. */
function SetupSummary({
  destination,
}: {
  destination: DeclaredDestination;
}): React.JSX.Element {
  const names = [
    ...(destination.table ? [destination.table.name] : []),
    ...Object.values(destination.tables ?? {}).map(table => table.name),
  ];

  if (names.length === 1)
    return (
      <p>
        Set up creates a {names[0]} table for this importer. Nothing is imported
        yet.
      </p>
    );

  return (
    <>
      <p>
        Set up creates {names.length} tables for this importer. Nothing is
        imported yet.
      </p>
      <ul>
        {names.map(name => (
          <li key={name}>{name}</li>
        ))}
      </ul>
    </>
  );
}

/** Where "Open imported data" goes: the table a single-table importer writes, or its first. */
function firstTable(config: JSONObject | undefined): string | undefined {
  if (typeof config?.table === 'string') return config.table;
  const tables = config?.tables;
  if (!tables || typeof tables !== 'object' || Array.isArray(tables))
    return undefined;
  const first = Object.values(tables)[0];

  return first &&
    typeof first === 'object' &&
    !Array.isArray(first) &&
    typeof first.table === 'string'
    ? first.table
    : undefined;
}

function maxBytes(accepts: DeclaredAccept[]): number {
  return Math.max(
    0,
    ...accepts.map(accept => accept.maxBytes ?? DEFAULT_ACCEPT_MAX_BYTES),
  );
}

function acceptAttribute(accepts: DeclaredAccept[]): string | undefined {
  const values = accepts.flatMap(accept => [
    ...(accept.extensions ?? []),
    ...(accept.mediaTypes ?? []),
  ]);

  return values.length ? values.join(',') : undefined;
}

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024)
    return `${Math.round((bytes / (1024 * 1024)) * 10) / 10} MB`;
  if (bytes >= 1024) return `${Math.round(bytes / 1024)} KB`;

  return `${bytes} bytes`;
}

/** UTF-8 when the file is valid UTF-8; older bank exports are often Windows-1252. */
export function decode(bytes: ArrayBuffer): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return new TextDecoder('windows-1252').decode(bytes);
  }
}

async function storedConfig(
  store: Store,
  drive: string,
  plugin: string,
  manifest: PluginManifest,
): Promise<JSONObject> {
  const terms = await pluginClassesFor(store, drive);
  const resource = await store.getResource(plugin);

  return pluginConfigFor(
    {
      schemas: resource.get(terms.properties['plugin-schemas']),
      connection: resource.get(terms.properties['plugin-connection']),
    },
    manifest.config,
  );
}
