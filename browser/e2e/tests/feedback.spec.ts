import { test, expect } from './fixtures';
import { before } from './test-utils';

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
  await page.getByTestId('sidebar').hover();
  await page.getByRole('button', { name: 'Feedback', exact: true }).click();
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
  await page.getByTestId('sidebar').hover();
  await page.getByRole('button', { name: 'Feedback', exact: true }).click();
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
