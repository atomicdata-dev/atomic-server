import { test, expect } from './fixtures';
import { before, clickAccountMenuItem } from './test-utils';

// The SDK uses a fake project and intercepted transport: no real reports in CI.
test.beforeEach(async ({ page }) => {
  await page.route('https://example.com/api/123/envelope/**', route =>
    route.fulfill({ status: 200, body: '{}', contentType: 'application/json' }),
  );
  await page.addInitScript(() => {
    (window as unknown as { __ATOMIC_SENTRY__: unknown }).__ATOMIC_SENTRY__ = {
      dsn: 'https://public@example.com/123',
      environment: 'test',
    };
  });
});
test.beforeEach(before);

test('sidebar feedback retains a failed report and retries successfully', async ({
  page,
  browserDiagnostics,
}) => {
  browserDiagnostics.expect(
    'error',
    /^Failed to load resource: the server responded with a status of 500/,
    'The first feedback transport attempt is deliberately rejected to verify retry',
    1,
    /^https:\/\/example.com\/api\/123\/envelope\//,
  );
  let status = 500;
  const reports: string[] = [];
  await page.route('https://example.com/api/123/envelope/**', async route => {
    const body = route.request().postData() ?? '';
    if (body.includes('"type":"feedback"')) reports.push(body);
    await route.fulfill({
      status,
      body: '{}',
      contentType: 'application/json',
      headers: { 'access-control-allow-origin': '*' },
    });
  });
  await clickAccountMenuItem(page, 'Feedback');
  const dialog = page.getByRole('dialog');
  const message = dialog.getByRole('textbox', {
    name: 'Feedback',
    exact: true,
  });
  const send = dialog.getByRole('button', {
    name: 'Send feedback',
    exact: true,
  });
  await expect(send).toBeDisabled();
  await message.fill('A synthetic feedback test');
  await send.click();
  await expect(dialog.getByRole('alert')).toContainText('could not be sent');
  await expect(message).toHaveValue('A synthetic feedback test');
  status = 200;
  await send.click();
  await expect(dialog.getByRole('status')).toContainText('has been received');
  expect(reports).toHaveLength(2);
  expect(reports[1]).toContain('A synthetic feedback test');
  await dialog.getByRole('button', { name: 'Close', exact: true }).click();
  await expect(dialog).not.toBeVisible();
});

test('disabled feedback explains availability without claiming a failed send', async ({
  page,
}) => {
  await page.addInitScript(() => {
    (window as unknown as { __ATOMIC_SENTRY__: unknown }).__ATOMIC_SENTRY__ = {
      dsn: '',
    };
  });
  await page.reload();
  await clickAccountMenuItem(page, 'Feedback');
  const dialog = page.getByRole('dialog');
  await expect(dialog).toContainText('Feedback reporting is unavailable');
  await expect(dialog).not.toContainText('could not be sent');
  await expect(
    dialog.getByRole('link', { name: 'info@ontola.io' }),
  ).toHaveAttribute('href', 'mailto:info@ontola.io');
  await dialog
    .getByRole('textbox', { name: 'Feedback', exact: true })
    .fill('A local suggestion');
  await expect(
    dialog.getByRole('button', { name: 'Send feedback', exact: true }),
  ).toBeDisabled();
});

test('local diagnostics are attached by default, can be declined, and exclude private context', async ({
  page,
}, testInfo) => {
  const reports: string[] = [];
  await page.route('https://example.com/api/123/envelope/**', async route => {
    const body = route.request().postData() ?? '';
    if (body.includes('"type":"feedback"')) reports.push(body);
    await route.fulfill({
      status: 200,
      body: '{}',
      contentType: 'application/json',
      headers: { 'access-control-allow-origin': '*' },
    });
  });
  await clickAccountMenuItem(page, 'Feedback');
  const dialog = page.getByRole('dialog');
  await expect(
    dialog.getByRole('checkbox', { name: 'Include diagnostic data' }),
  ).toBeVisible();
  await expect(
    dialog.getByRole('button', { name: 'Stop and clear' }),
  ).not.toBeVisible();
  const include = dialog.getByRole('checkbox', {
    name: 'Include diagnostic data',
  });
  await expect(include).toBeEnabled();
  await expect(include).toBeChecked();
  await page.evaluate(async () => {
    const resource = await window.store.newResource({
      parent: window.store.getDrive(),
      propVals: {
        'https://atomicdata.dev/properties/name': 'PRIVATE_DIAGNOSTIC_TEXT',
      },
    });
    await resource.save();
    window.history.replaceState(
      {},
      '',
      `${window.location.pathname}${window.location.search}${window.location.search ? '&' : '?'}secret=PRIVATE_DIAGNOSTIC_URL`,
    );
  });
  await expect(include).toBeChecked();
  await dialog.getByText('Diagnostic data', { exact: true }).click();
  await expect(
    dialog.getByRole('button', { name: 'Stop and clear' }),
  ).toBeVisible();
  const preview = dialog
    .getByRole('region', { name: 'Diagnostic report preview' })
    .locator('[data-code-text]');
  await expect(preview).toContainText(/save-started/);
  const previewText = (await preview.textContent())!;
  const report = JSON.parse(previewText);
  expect(report.schema).toBe(3);
  expect(report.events.map((event: { code: string }) => event.code)).toContain(
    'save-started',
  );
  expect(report.completeness.totalEvents).toBeGreaterThan(0);
  expect(report.eventMeanings['server-unconfirmed']).toContain(
    'may have applied',
  );
  expect(previewText).not.toContain('PRIVATE_DIAGNOSTIC');
  await expect(include).toBeChecked();
  expect(reports).toHaveLength(0);
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    dialog.getByRole('button', { name: 'Download report' }).click(),
  ]);
  expect(download.suggestedFilename()).toBe('atomic-diagnostics.json');
  expect(reports).toHaveLength(0);
  await page.screenshot({
    path: testInfo.outputPath('diagnostics-preview.png'),
  });
  await dialog
    .getByRole('textbox', { name: 'Feedback', exact: true })
    .fill('Synthetic diagnostic feedback');
  await dialog
    .getByRole('button', { name: 'Send feedback', exact: true })
    .click();
  await expect(dialog.getByRole('status')).toContainText('has been received');
  expect(reports).toHaveLength(1);
  const lines = reports[0].split('\n');
  const event = JSON.parse(lines[2]);
  expect(event.platform).toBe('javascript');
  expect(event.level).toBe('info');
  expect(event.request).toEqual({
    headers: { 'User-Agent': await page.evaluate(() => navigator.userAgent) },
  });
  expect(event.contexts.feedback.message).toBe('Synthetic diagnostic feedback');
  expect(JSON.parse(lines[3])).toMatchObject({
    type: 'attachment',
    filename: 'diagnostics.json',
    content_type: 'application/json',
  });
  expect(lines.slice(4).join('\n')).toBe(previewText);
  expect(reports[0]).not.toContain('PRIVATE_DIAGNOSTIC');
  await dialog.getByRole('button', { name: 'Close', exact: true }).click();
  await page.reload();
  await page.waitForFunction(() => !!window.store);
  expect(await page.evaluate(() => window.store.diagnostics.active)).toBe(true);
});

test('diagnostics survive reload and disabling clears IndexedDB across tabs', async ({
  page,
  context,
}) => {
  await page.waitForFunction(() => window.store?.diagnostics.active);
  await page.evaluate(() => {
    window.store.diagnostics.beginSave({})('error');
  });
  const readState = () =>
    page.evaluate(async () => {
      return new Promise<{
        enabled: boolean;
        sessions: Array<{ events: Array<{ code: string }> }>;
      }>((resolve, reject) => {
        const request = indexedDB.open('atomic-local-diagnostics-v1', 1);
        request.onerror = () => reject(request.error);

        request.onsuccess = () => {
          const db = request.result;
          const tx = db.transaction('state', 'readonly');
          const get = tx.objectStore('state').get('rolling');
          get.onsuccess = () => resolve(get.result);
          tx.oncomplete = () => db.close();
        };
      });
    });
  await expect
    .poll(async () =>
      (await readState()).sessions.some(s =>
        s.events.some(e => e.code === 'save-error'),
      ),
    )
    .toBe(true);
  await page.reload();
  await page.waitForFunction(() => window.store?.diagnostics.active);
  await clickAccountMenuItem(page, 'Feedback');
  const dialog = page.getByRole('dialog');
  await dialog.getByText('Diagnostic data', { exact: true }).click();
  const preview = dialog
    .getByRole('region', { name: 'Diagnostic report preview' })
    .locator('[data-code-text]');
  await expect(preview).toBeVisible();
  const report = JSON.parse((await preview.textContent())!);
  expect(
    report.previousSessions.some((s: { events: Array<{ code: string }> }) =>
      s.events.some(e => e.code === 'save-error'),
    ),
  ).toBe(true);
  const other = await context.newPage();
  await other.goto(page.url());
  await other.waitForFunction(() => window.store?.diagnostics.active);
  await dialog.getByRole('button', { name: 'Stop and clear' }).click();
  await expect.poll(async () => (await readState()).enabled).toBe(false);
  expect((await readState()).sessions).toEqual([]);
  await other.waitForFunction(
    () => window.store && !window.store.diagnostics.active,
  );
  await page.reload();
  await page.waitForFunction(() => !!window.store);
  await clickAccountMenuItem(page, 'Feedback');
  await page
    .getByRole('dialog')
    .getByText('Diagnostic data', { exact: true })
    .click();
  await expect(
    page.getByRole('button', { name: 'Start recording' }),
  ).toBeEnabled();
  expect(await page.evaluate(() => window.store.diagnostics.active)).toBe(
    false,
  );
  await other.close();
});
