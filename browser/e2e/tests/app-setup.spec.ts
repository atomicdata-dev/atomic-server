import { enableAIForTesting, setupScriptedToolCallMocks } from './ai-mock';
import { test, expect } from '@playwright/test';
import { before } from './test-utils';
test.beforeEach(before);

test('GitHub setup renders its declared inputs and host-owned credential without installing', async ({
  page,
}) => {
  await page.goto(new URL('/app/integrations', page.url()).href);
  await page
    .locator('[data-integration="github-issues"]')
    .getByRole('button', { name: 'Set up connection' })
    .click();
  const dialog = page.locator('dialog[open]');
  await expect(dialog.getByLabel('Repository', { exact: true })).toBeVisible();
  await expect(dialog.getByLabel('Sync into')).toBeEnabled();
  await dialog
    .getByLabel('Repository', { exact: true })
    .fill('ontola/atomic-server');
  await expect(
    dialog.getByRole('link', { name: 'Create GitHub token' }),
  ).toHaveAttribute('href', /target_name=ontola/);
  await expect(
    dialog.getByLabel('GitHub token', { exact: true }),
  ).toHaveAttribute('type', 'password');
  await dialog
    .getByLabel('Repository', { exact: true })
    .fill('https://github.com/ontola/atomic-server');
  await dialog
    .getByLabel('GitHub token', { exact: true })
    .fill('synthetic-not-a-credential');
  await dialog
    .getByRole('button', { name: 'Connect GitHub', exact: true })
    .click();
  await expect(dialog.getByRole('alert')).toContainText('owner/repository');
  await expect(
    dialog.getByRole('button', { name: 'Connect GitHub', exact: true }),
  ).toBeEnabled();
});

test('assistant discovers setup and opens the same form with known arguments', async ({
  page,
}) => {
  const state = await setupScriptedToolCallMocks(
    page,
    [
      { tool: 'list_app_setups', args: {} },
      {
        tool: 'setup_app',
        args: {
          app: 'github-issues',
          arguments: { repository: 'ontola/atomic-server' },
        },
      },
    ],
    'Complete the connection in the setup form.',
  );
  await enableAIForTesting(page);
  await page.reload();
  const sidebar = page.locator('[data-open]');
  const input = sidebar.locator('[contenteditable="true"]');
  await expect(input).toBeVisible();
  await input.fill('Connect our GitHub repository');
  const send = sidebar.getByTitle('Send');
  await expect(send).toBeEnabled({ timeout: 30000 });
  await send.click();
  const dialog = page.locator('dialog[open]');
  await expect(dialog.getByLabel('Repository', { exact: true })).toHaveValue(
    'ontola/atomic-server',
    { timeout: 30000 },
  );
  await expect(dialog.getByLabel('GitHub token', { exact: true })).toHaveValue(
    '',
  );
  await expect
    .poll(() => state.toolResults.join(' '))
    .toContain('needs_user_setup');
});
