import { test, expect, type Page } from '@playwright/test';
import { before, openWorkspaceDialog, waitForSynced } from './test-utils';
test.beforeEach(before);

/**
 * Diagnostics for the local-database key (#1767): which `keyval-store` records
 * exist, never their values. Session keys are reduced to a 4-byte SHA-256
 * prefix, enough to see whether the key changed across a reload. Logged and
 * attached so a CI failure shows which records were there.
 */
async function dumpDbKeyRecords(page: Page, label: string): Promise<void> {
  const report = await page.evaluate(async () => {
    const hex = (bytes: ArrayBuffer | Uint8Array, length: number) =>
      Array.from(new Uint8Array(bytes).slice(0, length))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
    const sha256 = (bytes: Uint8Array) =>
      crypto.subtle.digest('SHA-256', new Uint8Array(bytes));
    const subject = window.store?.getAgent()?.subject;
    const fingerprint = subject
      ? hex(await sha256(new TextEncoder().encode(subject)), 8)
      : undefined;
    const records = await new Promise<[string, unknown][]>(
      (resolve, reject) => {
        const open = indexedDB.open('keyval-store');
        open.onerror = () => reject(open.error);

        open.onsuccess = () => {
          const found: [string, unknown][] = [];
          const cursor = open.result
            .transaction('keyval')
            .objectStore('keyval')
            .openCursor();
          cursor.onerror = () => reject(cursor.error);

          cursor.onsuccess = () => {
            const current = cursor.result;

            if (!current) {
              open.result.close();
              resolve(found);

              return;
            }

            found.push([String(current.key), current.value]);
            current.continue();
          };
        };
      },
    );
    const keys: string[] = [];

    for (const [key, value] of records) {
      keys.push(
        key.startsWith('atomic.clientdb.session-key.') &&
          value instanceof Uint8Array
          ? `${key} (sha256 ${hex(await sha256(value), 4)})`
          : key,
      );
    }

    const hasWrappedDbKey =
      !!fingerprint &&
      records.some(
        ([key]) =>
          key === `atomic.clientdb.wrapped-key-v2.${fingerprint}` ||
          key === `atomic.clientdb.wrapped-key.${fingerprint}`,
      );

    return { subject, fingerprint, hasWrappedDbKey, keys };
  });
  const text = JSON.stringify({ label, ...report }, null, 2);
  // oxlint-disable-next-line no-console -- meant for the CI log
  console.log(`[db-key diagnostics] ${text}`);
  await test.info().attach(`db-key records: ${label}`, {
    body: text,
    contentType: 'application/json',
  });
}

test('workspace owns its views and links to separate connection settings', async ({
  page,
}) => {
  // This test installs a connection, navigates, reloads twice and walks four
  // settings tabs, and two of its steps are now allowed 45s each because the
  // resources behind them are read local-first. It measured 25s alone and
  // failed the 60s default under four local workers with 20s still to run, so
  // fixing only the assertions would move the failure onto the test budget.
  test.setTimeout(240_000);

  const installed = await page.evaluate(async () => {
    const store = window.store!;
    const drive = store.getDrive()!;
    const {
      core,
      dataBrowser,
      ensureSchema,
      pinPluginRelease,
      pluginSchema,
      taskSchema,
    } = window.atomicE2E.tomicLib;

    // A connected integration, built here rather than by installing a real
    // provider. This test is about what the workspace page does with a
    // connection — its own views, and a link out to connection settings — so
    // the connection only has to exist and be shaped right. Plugins
    // themselves live in atomic-plugins; nothing in this repo installs one.
    const schema = await ensureSchema(store, drive, pluginSchema());

    const save = async (resource: { save(): Promise<string> }) => {
      if ((await resource.save()) !== 'persisted')
        throw new Error('AtomicServer disconnected while building the fixture');
    };

    const plugin = await store.newResource({
      parent: drive,
      isA: [schema.classes['plugin-script']],
      propVals: {
        [core.properties.name]: 'Workspace fixture',
        [dataBrowser.properties.emoji]: '🧪',
        [schema.properties['plugin-source']]:
          'export const manifest = { schemaVersion: 1, operations: [], secrets: [] };\n' +
          'export function run() { return { intents: [], problems: [] }; }',
      },
    });
    await save(plugin);

    // The kanban columns the assertions below read are the embedded task
    // vocabulary's Tag resources, so the table groups by task status. Its
    // class must carry that property: a kanban over a class with no select
    // property tries to add a Status one, which a built-in class like
    // `core.classes.class` never accepts, and the board never leaves
    // "Setting up the board…".
    const status = await store.getResource(taskSchema.properties.status);
    const rowClass = await store.newResource({
      parent: drive,
      isA: [core.classes.class],
      propVals: {
        [core.properties.shortname]: 'fixture-task',
        [core.properties.description]: 'A row of the workspace fixture.',
        [core.properties.recommends]: [core.properties.name, status.subject],
      },
    });
    await save(rowClass);
    const table = await store.newResource({
      parent: plugin.subject,
      isA: [dataBrowser.classes.table],
      propVals: {
        [core.properties.name]: 'Fixture workspace',
        [core.properties.classtype]: rowClass.subject,
      },
    });
    await save(table);

    const view = await store.newResource({
      parent: table.subject,
      isA: [dataBrowser.classes.view],
      propVals: {
        [core.properties.name]: 'Kanban',
        [dataBrowser.properties.viewKind]: 'kanban',
        [dataBrowser.properties.viewGroupBy]: status.subject,
        [dataBrowser.properties.viewColumns]: [
          core.properties.name,
          status.subject,
        ],
      },
    });
    await save(view);
    await table.set(dataBrowser.properties.tableViews, [view.subject]);
    await table.set(dataBrowser.properties.tableDefaultView, view.subject);
    await save(table);

    const pinned = await pinPluginRelease(store, {
      drive,
      plugin: plugin.subject,
    });
    await plugin.set(schema.properties['plugin-connection'], {
      release: pinned.id,
      config: { drive, plugin: plugin.subject, table: table.subject },
      events: [],
    });
    await save(plugin);

    // A second view, so the assertions can tell the workspace's own views
    // apart from the one the fixture starts with.
    const views = table.get(
      'https://atomicdata.dev/properties/table-views',
    ) as string[];
    const extra = await store.newResource({
      parent: table.subject,
      isA: view.get('https://atomicdata.dev/properties/isA'),
      propVals: {
        'https://atomicdata.dev/properties/name': 'All rows',
        'https://atomicdata.dev/properties/view-kind': 'table',
      },
    });
    await save(extra);
    await table.set('https://atomicdata.dev/properties/table-views', [
      ...views,
      extra.subject,
    ]);
    await save(table);

    return { plugin: plugin.subject, table: table.subject };
  });
  // Everything above was written through the store in this page. Navigating
  // on top of an outbox that has not drained is the race `apps.spec.ts`
  // documents: the write the UI has already accepted is gone after the
  // navigation. Twenty-four other spec files wait here; this one did not.
  await waitForSynced(page);

  await page.goto(
    new URL(
      `/app/show?subject=${encodeURIComponent(installed.table)}`,
      page.url(),
    ).href,
  );
  await expect(
    page.getByRole('heading', { name: 'Secrets', exact: false }),
  ).not.toBeVisible();
  await expect(
    page.getByRole('heading', { name: 'Source', exact: true }),
  ).not.toBeVisible();
  // The kanban column headings are four Tag resources of the embedded task
  // vocabulary (`https://atomicdata.dev/task/v1/{todo,doing,blocked,done}`),
  // and until they load the header renders `useTitle`'s loading placeholder,
  // so the whole board reads `... 0`. That is what this used to fail on, and
  // the cause was not this test: reaching them was local-first, and
  // `fetchResourceWithLocalFallback` would not ask the server until a
  // client-database read in the WASM worker had answered. Measured under four
  // local Playwright workers, that one worker round trip cost 3965 ms while
  // the host answered the same four subjects in 1.5 to 2.1 ms, and raising
  // this assertion to 45 s was not enough — it failed at 45 s too.
  //
  // Fixed in `Store.fetchResourceWithLocalFallback`, which now asks the host
  // for embedded vocabulary directly. The budget stays because the rest of
  // this page is still read local-first, but it should no longer be near it.
  await expect(page.getByText('Todo', { exact: true }).first()).toBeVisible({
    timeout: 45_000,
  });
  await page.screenshot({
    path: '/tmp/atomic-integration-workspace.png',
    fullPage: true,
    animations: 'disabled',
  });
  await openWorkspaceDialog(page, 'connections');
  const allSettings = page.getByRole('link', {
    name: 'Connection settings',
    exact: true,
  });
  await expect(allSettings).toHaveCount(1);
  const settings = allSettings;
  await expect(settings).toHaveAttribute('href', installed.plugin);
  await settings.click();
  await expect(
    page.getByRole('link', { name: 'Open workspace', exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole('tab', { name: 'Workspace', exact: true }),
  ).toHaveCount(0);
  await page.getByRole('tab', { name: 'Settings', exact: true }).click();
  await expect(page.getByLabel('Opening view')).toBeVisible();
  await page.getByLabel('Opening view').selectOption({ label: 'All rows' });
  await expect(page.getByRole('heading', { name: /Secrets/ })).toBeVisible();
  await page.getByRole('tab', { name: 'Code', exact: true }).click();
  await expect(
    page.getByRole('heading', { name: 'Source', exact: true }),
  ).toBeVisible();
  await page.getByRole('tab', { name: 'Automations', exact: true }).click();
  await expect(
    page.getByRole('button', { name: 'New automation' }),
  ).toBeVisible();
  // The opening-view setting is a write; reloading before it has gone out is
  // the same race as the navigation above.
  await waitForSynced(page);
  await page.reload();
  await page.getByRole('tab', { name: 'Settings', exact: true }).click();
  // Each `<option>` is a view resource rendered by name, so this is the same
  // local-first read as the kanban headings and shows the same `...` until it
  // lands. Seen under four workers as
  //
  //     <option value="did:ad:_3wWljDq…">...</option>
  //
  // still unresolved sixteen polls in.
  await expect(
    page.getByLabel('Opening view').locator('option:checked'),
  ).toHaveText('All rows', { timeout: 45_000 });
  await page.getByRole('tab', { name: 'Sync', exact: true }).click();
  let releasePreview!: () => void;
  const previewGate = new Promise<void>(resolve => {
    releasePreview = resolve;
  });
  await page.route('**/plugin-sync-preview', async route => {
    await previewGate;
    await route.fulfill({
      status: 500,
      contentType: 'text/plain',
      body: 'Provider unavailable. Try again.',
    });
  });
  await page.getByRole('button', { name: 'Preview sync', exact: true }).click();
  await expect(
    page.getByRole('button', { name: 'Preparing preview…' }),
  ).toHaveAttribute('aria-busy', 'true');
  await expect(
    page.getByRole('button', { name: 'Preparing preview…' }),
  ).toBeDisabled();
  releasePreview();
  await expect(
    page.getByRole('alert').filter({ hasText: 'Provider unavailable' }),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Preview sync', exact: true }),
  ).toBeEnabled();

  for (const tab of ['Sync', 'Automations', 'Settings', 'Activity', 'Code']) {
    await page.getByRole('tab', { name: tab, exact: true }).click();
    await page.screenshot({
      path: `/tmp/atomic-tab-${tab}.png`,
      animations: 'disabled',
    });
  }

  await page.getByRole('button', { name: 'Edit with AI', exact: true }).click();
  await expect(
    page.getByText('Help me edit this integration.', { exact: false }).first(),
  ).toBeVisible();
});

test('workspace starts automation chat without requiring a connection', async ({
  page,
}) => {
  await dumpDbKeyRecords(page, 'after devDrive');
  const table = await page.evaluate(async () => {
    const resource = await window.store!.newResource({
      parent: window.store!.getDrive(),
      isA: 'https://atomicdata.dev/classes/Table',
      propVals: {
        'https://atomicdata.dev/properties/name': 'Independent workspace',
        'https://atomicdata.dev/properties/classtype':
          'https://atomicdata.dev/classes/Folder',
      },
    });
    await resource.save();

    return resource.subject;
  });
  await page.goto(
    new URL(`/app/show?subject=${encodeURIComponent(table)}`, page.url()).href,
  );
  await openWorkspaceDialog(page, 'automations');
  await expect(
    page.getByText('No automations yet.', { exact: true }),
  ).toBeVisible();
  await page
    .getByRole('button', { name: 'New automation', exact: true })
    .click();
  await expect(
    page
      .getByText('Help me create a new automation.', { exact: false })
      .first(),
  ).toBeVisible();
  // The workspace dialog must be gone — but not "no dialog at all": with no AI
  // provider configured, `askAI` legitimately raises the model-setup dialog
  // (`AISetupPanel`), and that is what this used to catch.
  await expect(
    page.getByRole('dialog').getByText('No automations yet.', { exact: true }),
  ).not.toBeVisible();
  const automation = await page.evaluate(async workspace => {
    const { createPlugin } = window.atomicE2E.runScript;

    return createPlugin(
      window.store!,
      {
        parent: window.store!.getDrive()!,
        drive: window.store!.getDrive()!,
        workspace,
        connections: [],
      },
      'Local reminder',
      'export function run() { return { intents: [], problems: [] }; }',
    );
  }, table);
  await page.goto(
    new URL(`/app/show?subject=${encodeURIComponent(automation)}`, page.url())
      .href,
  );
  await dumpDbKeyRecords(page, 'after reload to the automation');
  await expect(
    page.getByRole('tab', { name: 'Automation', exact: true }),
  ).toBeVisible();
  await page.getByRole('link', { name: 'Open workspace', exact: true }).click();
  await openWorkspaceDialog(page, 'automations');
  await expect(
    page.getByRole('dialog').getByRole('link', { name: /Local reminder/ }),
  ).toBeVisible();
});
