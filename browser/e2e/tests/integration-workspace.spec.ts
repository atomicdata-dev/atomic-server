import { test, expect } from '@playwright/test';
import { before } from './test-utils';
test.beforeEach(before);

test('integration opens its board and keeps code and credentials in settings tabs', async ({
  page,
}) => {
  const plugin = await page.evaluate(async () => {
    await import('/src/chunks/PluginRuns/ConnectGitHub.tsx');
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

    return connection.plugin;
  });
  await page.goto(
    new URL(`/app/show?subject=${encodeURIComponent(plugin)}`, page.url()).href,
  );
  await expect(
    page.getByRole('tab', { name: 'Workspace', exact: true }),
  ).toHaveAttribute('data-state', 'active');
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
