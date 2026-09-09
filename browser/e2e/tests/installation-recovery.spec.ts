import { resolve } from 'node:path';
import { test, expect } from '@playwright/test';
import type { Resource } from '@tomic/lib';
import { before } from './test-utils';
test.beforeEach(before);
test('table installation reuses saved class after a lost receipt', async ({
  page,
}) => {
  const result = await page.evaluate(async () => {
    const path = '/src/chunks/TablePage/createTableFromSpec.ts';
    const { buildTableFromSpec, resolveOntologyParent } = await import(
      /* @vite-ignore */ path
    );
    const store = window.store!;
    const driveSubject = store.getDrive()!;
    const ontology = await store.getResource(
      await resolveOntologyParent(store, driveSubject),
    );

    const addToOntology = async (resource: Resource) => {
      await resource.save();
      await ontology.push(
        'https://atomicdata.dev/properties/classes',
        [resource.subject],
        true,
      );
      await ontology.save();
    };

    const spec = {
      name: 'Recoverable tasks',
      rowName: 'Task',
      columns: [
        { name: 'Status', type: 'select', options: ['Todo', 'Done'] },
        { name: 'Note', type: 'text' },
      ],
      views: [
        {
          name: 'Board',
          kind: 'kanban',
          groupByColumn: 'Status',
          default: true,
        },
      ],
    };
    const opts = {
      parent: driveSubject,
      driveSubject,
      addToOntology,
      installationKey: 'recovery-fixture',
    };
    const original = store.newResource.bind(store);
    let savedClass = '';

    store.newResource = async options => {
      const resource = await original(options);

      if (
        !savedClass &&
        String(
          options?.propVals?.['https://atomicdata.dev/properties/localId'],
        ).startsWith('installation:')
      ) {
        const save = resource.save.bind(resource);

        resource.save = async () => {
          await save();
          savedClass = resource.subject;
          resource.save = save;
          throw new Error('Lost setup receipt after save');
        };
      }

      return resource;
    };

    let failed = false;

    try {
      await buildTableFromSpec(store, spec, opts);
    } catch (e) {
      failed = String(e).includes('Lost setup receipt');
    } finally {
      store.newResource = original;
    }

    if (!failed)
      throw new Error('Fault injection did not reach a committed setup step');
    const retry = await buildTableFromSpec(store, spec, opts);
    const repeat = await buildTableFromSpec(store, spec, opts);

    return { savedClass, retry, repeat };
  });
  expect(result.savedClass).toBeTruthy();
  expect(result.retry.classSubject).toBe(result.savedClass);
  expect(result.repeat).toEqual(result.retry);
});

test('duplicate import review links both copies and blocks apply', async ({
  page,
}) => {
  const protocolModule = '/@fs' + resolve(__dirname, '../../lib/src/ws-v2.ts');
  const fixture = await page.evaluate(async protocolPath => {
    const store = window.store!;
    const drive = store.getDrive()!;
    const copies = [];

    for (const name of ['Offline copy A', 'Offline copy B']) {
      const resource = await store.newResource({
        parent: drive,
        propVals: { 'https://atomicdata.dev/properties/name': name },
      });
      await resource.save();
      copies.push(resource.subject);
    }

    // Simulate two previously independent replica histories over the real,
    // authenticated transport. Authoring another duplicate would correctly fail.
    const { encodeSyncPush } = await import(/* @vite-ignore */ protocolPath);
    const entries = [];

    for (const subject of copies) {
      const resource = await store.getResource(subject);
      const doc = resource.getLoroDoc()!.fork();
      doc
        .getMap('properties')
        .set('https://atomicdata.dev/properties/localId', 'test:offline-copy');
      entries.push({ subject, loroBytes: doc.export({ mode: 'snapshot' }) });
    }

    (
      store.getDefaultWebSocket() as unknown as {
        sendBinary(frame: Uint8Array): void;
      }
    ).sendBinary(encodeSyncPush(drive, entries));
    const property = await store.newResource({
      parent: drive,
      propVals: {
        'https://atomicdata.dev/properties/isA': [
          'https://atomicdata.dev/classes/Property',
        ],
        'https://atomicdata.dev/properties/shortname': 'linked-project',
        'https://atomicdata.dev/properties/name': 'Project link',
        'https://atomicdata.dev/properties/description':
          'Project connected to this task',
        'https://atomicdata.dev/properties/datatype':
          'https://atomicdata.dev/datatypes/atomicURL',
      },
    });
    await property.save();
    const linked = await store.newResource({
      parent: drive,
      propVals: {
        'https://atomicdata.dev/properties/name': 'Linked task',
        [property.subject]: copies[1],
      },
    });
    await linked.save();
    const edited = await store.newResource({
      parent: drive,
      propVals: {
        'https://atomicdata.dev/properties/name': 'Task edited after preview',
        [property.subject]: copies[1],
      },
    });
    await edited.save();
    const path = '/src/chunks/PluginRuns/runScript.ts';
    const { createPlugin } = await import(/* @vite-ignore */ path);
    const plugin = await createPlugin(
      store,
      { drive, parent: drive },
      'Collision review fixture',
      `export function run() { return ${JSON.stringify({ intents: [], problems: [{ severity: 'error', message: 'Duplicate source', importCollision: copies }] })}; }`,
    );

    return {
      plugin,
      primary: copies[0],
      retained: copies[1],
      linked: linked.subject,
      edited: edited.subject,
      property: property.subject,
    };
  }, protocolModule);
  await expect
    .poll(() =>
      page.evaluate(async () => {
        const store = window.store!;

        try {
          await store.findByLocalId(
            store.getDrive()!,
            store.getDrive()!,
            'test:offline-copy',
          );

          return false;
        } catch (error) {
          return String(error).includes('Ambiguous');
        }
      }),
    )
    .toBe(true);
  const url = new URL(page.url());
  url.searchParams.set('subject', fixture.plugin);
  await page.goto(url.href);
  await page.getByRole('button', { name: 'Run', exact: true }).click();
  await expect(
    page.getByText('Duplicate source records', { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole('link', { name: 'Offline copy A', exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole('link', { name: 'Offline copy B', exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Apply 0 changes', exact: true }),
  ).toBeDisabled();
  await page
    .getByRole('button', { name: 'Review copies', exact: true })
    .click();
  await expect(
    page.getByText('Different values', { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Save primary record', exact: true }),
  ).toBeDisabled();
  await page
    .getByRole('group', { name: 'Offline copy A', exact: true })
    .getByRole('button', { name: 'Use as primary', exact: true })
    .click();
  await page
    .getByRole('group', { name: 'Value from Offline copy B', exact: true })
    .getByRole('button', { name: 'Use this value' })
    .click();
  await page
    .getByRole('button', { name: 'Save primary record', exact: true })
    .click();
  await expect(
    page.getByRole('status').filter({ hasText: 'Primary record saved' }),
  ).toBeVisible();
  const result = await page.evaluate(async () => {
    const store = window.store!;
    const primary = await store.findByLocalId(
      store.getDrive()!,
      store.getDrive()!,
      'test:offline-copy',
    );

    return primary?.get('https://atomicdata.dev/properties/name');
  });
  expect(result).toBe('Offline copy B');
  await page
    .getByRole('button', { name: 'Find links to these copies' })
    .click();
  await expect(
    page.getByRole('button', { name: 'Update selected links' }),
  ).toBeVisible();
  await page
    .getByRole('button', { name: 'Update selected links' })
    .scrollIntoViewIfNeeded();
  await page.screenshot({
    path: '/tmp/atomic-reference-review.png',
    fullPage: true,
  });
  await page.evaluate(async ({ edited, property }) => {
    const record = await window.store!.getResource(edited);
    await record.set(property, 'https://example.com/manually-selected');
    await record.save();
  }, fixture);
  await page.getByRole('button', { name: 'Update selected links' }).click();
  await expect(
    page.getByRole('status').filter({ hasText: 'Links confirmed' }),
  ).toBeVisible();
  await expect(
    page.getByRole('alert').filter({ hasText: 'Links changed since review' }),
  ).toBeVisible();
  const saved = await page.evaluate(async f => {
    const store = window.store!;

    return {
      linked: (await store.readServerSnapshot(f.linked))[f.property],
      edited: (await store.readServerSnapshot(f.edited))[f.property],
      original: (await store.readServerSnapshot(f.retained))[
        'https://atomicdata.dev/properties/name'
      ],
    };
  }, fixture);
  expect(saved).toEqual({
    linked: fixture.primary,
    edited: 'https://example.com/manually-selected',
    original: 'Offline copy B',
  });
  await page.getByRole('button', { name: 'Refresh link review' }).click();
  await expect(
    page.getByText('No supported links found in this drive.'),
  ).toBeVisible();
  url.searchParams.set('subject', fixture.primary);
  await page.goto(url.href);
  await page
    .getByText('Review links to original copies', { exact: true })
    .click();
  await page
    .getByRole('button', { name: 'Find links to these copies' })
    .click();
  await expect(
    page.getByText('No supported links found in this drive.'),
  ).toBeVisible();
});
