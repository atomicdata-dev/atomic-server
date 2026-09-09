import { test, expect } from '@playwright/test';
import { before } from './test-utils';
test.beforeEach(before);

test('workspace owns its views and links to separate connection settings', async ({
  page,
}) => {
  const installed = await page.evaluate(async () => {
    const setupPath = '/src/chunks/PluginRuns/ConnectGitHub.tsx';
    await import(/* @vite-ignore */ setupPath);
    // Vite serves the installer after loading its owning UI module.
    const ui = await fetch('/src/chunks/PluginRuns/ConnectGitHub.tsx').then(r =>
      r.text(),
    );
    const path = ui.match(
      /"([^"]*integrations\/github-issues\/atomic[^"]*)"/,
    )![1];
    const { install } = await import(path);
    const sourceModule = await import(
      path.replace(/atomic\.ts.*$/, 'plugin.js?raw')
    );
    const source = sourceModule.default;
    const store = window.store!;
    const connection = await install(
      store,
      store.getDrive(),
      'ontola/workspace-test',
      source,
    );
    // Existing installations retain their JSON binding, without a write-on-read migration.
    const { findSchema, pluginSchema } = await import(
      path.replace(
        /integrations\/github-issues\/atomic\.ts.*$/,
        'browser/lib/src/index.ts',
      )
    );
    const schema = await findSchema(store, store.getDrive(), pluginSchema());
    const legacy = await store.getResource(connection.plugin);
    await legacy.remove(schema.properties['plugin-workspace']);
    await legacy.save();
    const table = await store.getResource(connection.table);
    const views = table.get(
      'https://atomicdata.dev/properties/table-views',
    ) as string[];
    const original = await store.getResource(views[0]);
    const extra = await store.newResource({
      parent: connection.table,
      isA: original.get('https://atomicdata.dev/properties/isA'),
      propVals: {
        'https://atomicdata.dev/properties/name': 'All issues',
        'https://atomicdata.dev/properties/view-kind': 'table',
      },
    });
    await extra.save();
    await table.set('https://atomicdata.dev/properties/table-views', [
      ...views,
      extra.subject,
    ]);
    await table.save();

    return { plugin: connection.plugin, table: connection.table };
  });
  await page.goto(
    new URL(
      `/app/show?subject=${encodeURIComponent(installed.table)}`,
      page.url(),
    ).href,
  );
  await expect(
    page.getByRole('button', { name: 'Connections', exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole('heading', { name: 'Secrets', exact: false }),
  ).not.toBeVisible();
  await expect(
    page.getByRole('heading', { name: 'Source', exact: true }),
  ).not.toBeVisible();
  await expect(page.getByText('Todo', { exact: true }).first()).toBeVisible();
  await page.screenshot({
    path: '/tmp/atomic-integration-workspace.png',
    fullPage: true,
    animations: 'disabled',
  });
  await page.getByRole('button', { name: 'Connections', exact: true }).click();
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
  await page.getByLabel('Opening view').selectOption({ label: 'All issues' });
  await expect(page.getByRole('heading', { name: /Secrets/ })).toBeVisible();
  await page.getByRole('tab', { name: 'Code', exact: true }).click();
  await expect(
    page.getByRole('heading', { name: 'Source', exact: true }),
  ).toBeVisible();
  await page.getByRole('tab', { name: 'Automations', exact: true }).click();
  await expect(
    page.getByRole('button', { name: 'New automation' }),
  ).toBeVisible();
  await page.reload();
  await page.getByRole('tab', { name: 'Settings', exact: true }).click();
  await expect(
    page.getByLabel('Opening view').locator('option:checked'),
  ).toHaveText('All issues');
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
  await page.getByRole('button', { name: 'Automations', exact: true }).click();
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
  await expect(page.getByRole('dialog')).not.toBeVisible();
  const automation = await page.evaluate(async workspace => {
    const scriptPath = '/src/chunks/PluginRuns/runScript.ts';
    const { createPlugin } = await import(/* @vite-ignore */ scriptPath);

    return createPlugin(
      window.store!,
      {
        parent: window.store!.getDrive(),
        drive: window.store!.getDrive(),
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
  await expect(
    page.getByRole('tab', { name: 'Automation', exact: true }),
  ).toBeVisible();
  await page.getByRole('link', { name: 'Open workspace', exact: true }).click();
  await page.getByRole('button', { name: 'Automations', exact: true }).click();
  await expect(
    page.getByRole('dialog').getByRole('link', { name: /Local reminder/ }),
  ).toBeVisible();
});
