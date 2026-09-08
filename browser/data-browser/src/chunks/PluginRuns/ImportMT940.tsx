import pluginWorkerUrl from '@tomic/lib/plugin-run.worker.js?url';
import { useEffect, useState } from 'react';
import {
  runPlugin,
  core,
  dataBrowser,
  ensureSchema,
  findSchema,
  pluginSchema,
  readConnectionSubjects,
  executeServerPlugin,
  useStore,
  type Resource,
} from '@tomic/react';
import { Button } from '@components/Button';
import { Column } from '@components/Row';
import Field from '@components/forms/Field';
import { Input, ErrMessage } from '@components/forms/InputStyles';
import { BasicSelect } from '@components/forms/BasicSelect';
import { ExternalLink } from '@components/ExternalLink';
import { AtomicLink } from '@components/AtomicLink';
import { bankingSchema } from '../../../../../integrations/mt940/schema';
import type { Config } from '../../../../../integrations/mt940/plugin';
import source from '../../../../../integrations/mt940/plugin.js?raw';
import { pluginClassesFor } from './runScript';
import { ensureInstallationResource } from './installationResources';
import { RunPluginDialog } from './RunPluginDialog';

export function ImportMT940({
  drive,
  initialTarget,
}: {
  drive: string;
  initialTarget?: string;
}) {
  const store = useStore();
  const [file, setFile] = useState<File>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [existing, setExisting] = useState<
    Array<{ subject: string; name: string; config: Config }>
  >([]);
  const [target, setTarget] = useState('');
  const [instance, setInstance] = useState<{
    resource: Resource;
    config: Config;
  }>();
  const [verdict, setVerdict] = useState<string>();
  const [imported, setImported] = useState(false);
  useEffect(() => {
    let active = true;
    void (async () => {
      const schema = await findSchema(store, drive, pluginSchema());
      const klass = schema.classes?.['plugin-script'];
      const schemaProperty = schema.properties?.['plugin-schemas'];
      if (!klass || !schemaProperty) return;
      const subjects = await readConnectionSubjects(
        store,
        drive,
        core.properties.isA,
        klass,
      );
      const choices = [];

      for (const subject of subjects) {
        const resource = await store.getResource(subject);
        const value = resource.get(schemaProperty) as
          | { mt940?: Config }
          | undefined;
        if (value?.mt940)
          choices.push({ subject, name: resource.title, config: value.mt940 });
      }

      if (active) {
        setExisting(choices);
        setTarget(initialTarget ?? choices[0]?.subject ?? '');
      }
    })().catch(reason => {
      if (active) setError(String(reason));
    });

    return () => {
      active = false;
    };
  }, [store, drive, initialTarget]);

  const preview = async () => {
    if (!file || busy) return;
    setBusy(true);
    setError('');
    setImported(false);

    try {
      if (file.size > 512_000)
        throw new Error(
          'Choose a statement smaller than 512 KB. Export a shorter period if needed.',
        );
      const bytes = await file.arrayBuffer();
      // Prefer UTF-8, but older MT940 bank exports often use Windows-1252.
      let text: string;

      try {
        text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      } catch {
        text = new TextDecoder('windows-1252').decode(bytes);
      }

      const validation = await runPlugin(
        source,
        {
          trigger: {
            kind: 'manual',
            at: Date.now(),
            payload: { text, validate: true },
          },
        },
        {
          createWorker: () =>
            new Worker(pluginWorkerUrl, { type: 'module' }) as never,
        },
      );
      const invalid = validation.verdict.problems.find(
        problem => problem.severity === 'error',
      );
      if (validation.timedOut || invalid)
        throw new Error(
          invalid?.message ??
            'Statement validation timed out. Export a shorter period.',
        );
      let current = instance;

      if (!current && target) {
        const selected = existing.find(item => item.subject === target);
        if (!selected)
          throw new Error(
            'Choose an existing bank importer or create a new one.',
          );
        current = {
          resource: await store.getResource(target),
          config: selected.config,
        };
      }

      if (!current) {
        const pluginTerms = await pluginClassesFor(store, drive);
        const resource = await ensureInstallationResource(store, drive, {
          parent: drive,
          localId: 'atomic:mt940:installation',
          isA: [pluginTerms.classes['plugin-script']],
          propVals: {
            [core.properties.name]: 'Bank statements',
            [pluginTerms.properties['plugin-source']]: source,
            [pluginTerms.properties['plugin-schemas']]: {},
            [pluginTerms.properties.trigger]: 'manual',
          },
        });
        const subject = resource.subject;
        await resource.set(dataBrowser.properties.emoji, '🏦');
        await resource.save();
        const terms = await ensureSchema(store, drive, bankingSchema());
        const table = await ensureInstallationResource(store, drive, {
          parent: subject,
          localId: 'atomic:mt940:table',
          isA: [dataBrowser.classes.table],
          propVals: {
            [core.properties.name]: 'Bank transactions',
            [core.properties.classtype]: terms.classes['bank-transaction'],
          },
        });
        await table.save();
        const view = await ensureInstallationResource(store, drive, {
          parent: table.subject,
          localId: 'atomic:mt940:default-view',
          isA: [dataBrowser.classes.view],
          propVals: {
            [core.properties.name]: 'Transactions',
            [dataBrowser.properties.viewKind]: 'table',
            [dataBrowser.properties.viewColumns]: [
              'bank-booking-date',
              'bank-description',
              'bank-amount',
              'bank-currency',
              'bank-account',
              'bank-reference',
            ].map(key => terms.properties[key]),
          },
        });
        await view.save();
        await table.set(dataBrowser.properties.tableViews, [view.subject]);
        await table.set(dataBrowser.properties.tableDefaultView, view.subject);
        await table.save();
        const config = {
          table: table.subject,
          rowClass: terms.classes['bank-transaction'],
          properties: terms.properties,
        };
        const schema = await ensureSchema(store, drive, pluginSchema());
        await resource.set(schema.properties['plugin-schemas'], {
          mt940: config,
        });
        await resource.save();
        current = { resource, config };
      }

      setInstance(current);
      const result = await executeServerPlugin(store, {
        drive,
        plugin: current.resource.subject,
        source,
        input: {
          text,
          config: current.config,
          trigger: {
            kind: 'manual',
            at: Date.now(),
            subject: current.resource.subject,
          },
        },
      });
      if (result.error || !result.verdict)
        throw new Error(result.error ?? 'The importer returned no preview.');
      setVerdict(result.verdict);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Column gap='0.75rem'>
      <p>
        Import bank transactions from an MT940 statement. No bank connection or
        token is needed.
      </p>
      <p>
        In bunq: open your bank account, choose Settings, then Export statement
        and select MT940.
      </p>
      <ExternalLink to='https://help.bunq.com/en-ie/articles/how-do-i-export-a-bank-statement'>
        bunq export instructions
      </ExternalLink>
      <Field fieldId='mt940-target' label='Import into'>
        <BasicSelect
          id='mt940-target'
          value={target}
          disabled={busy || !!instance}
          onChange={event => setTarget(event.target.value)}
        >
          <option value=''>Default Bank transactions table</option>
          {existing.map(item => (
            <option key={item.subject} value={item.subject}>
              {item.name}
            </option>
          ))}
        </BasicSelect>
      </Field>
      <Field fieldId='mt940-file' label='Bank statement file'>
        <Input
          id='mt940-file'
          type='file'
          accept='.mt940,.sta,.940,.txt'
          disabled={busy}
          onChange={event => {
            setFile(event.target.files?.[0]);
            setError('');
            setImported(false);
          }}
        />
      </Field>
      <p>
        Your file is processed in the plugin sandbox on your AtomicServer.
        Review transactions before saving them. Up to 500 transactions per file.
      </p>
      <Button disabled={busy || !file} onClick={preview}>
        {busy ? 'Preparing preview…' : 'Preview import'}
      </Button>
      {error && <ErrMessage role='alert'>{error}</ErrMessage>}
      {imported && instance && (
        <AtomicLink subject={instance.config.table}>
          Open bank transactions
        </AtomicLink>
      )}
      {verdict && instance && (
        <RunPluginDialog
          resource={instance.resource}
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
