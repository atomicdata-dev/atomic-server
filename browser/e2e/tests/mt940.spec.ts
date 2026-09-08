import { test, expect } from '@playwright/test';
import { before } from './test-utils';
const statement = `:20:SYNTHETIC
:25:NL00BUNQ0000000000
:28C:1/1
:60F:C260901EUR100,00
:61:2609020902D12,34NTRFNONREF//TEST-1
:86:Fixture lunch
:61:2609030903C20,00NTRFNONREF//TEST-2
:86:Fixture refund
:62F:C260903EUR107,66
`;
test.beforeEach(before);
test('MT940 rejects unbalanced files, previews in sandbox and skips repeat imports', async ({
  page,
}) => {
  await page.goto(new URL('/app/integrations', page.url()).href);
  const card = page.locator('[data-integration="mt940"]');
  await card.getByText('Repository test results', { exact: true }).click();
  await expect(card.getByText(/Offline checks passed:/)).toBeVisible();
  await page
    .locator('[data-integration="mt940"]')
    .getByRole('button', { name: 'Set up connection' })
    .click();
  const upload = page.locator('#mt940-file');
  await upload.setInputFiles({
    name: 'broken.mt940',
    mimeType: 'text/plain',
    buffer: Buffer.from(statement.replace('107,66', '107,67')),
  });
  await page
    .getByRole('button', { name: 'Preview import', exact: true })
    .click();
  await expect(page.getByRole('alert')).toContainText('does not reconcile');
  await upload.setInputFiles({
    name: 'synthetic.mt940',
    mimeType: 'text/plain',
    buffer: Buffer.from(statement),
  });
  await page
    .getByRole('button', { name: 'Preview import', exact: true })
    .click();
  await expect(
    page.getByRole('button', { name: /Apply 2 changes/ }),
  ).toBeVisible({ timeout: 30000 });
  await page.getByRole('button', { name: /Apply 2 changes/ }).click();
  await expect(
    page.getByRole('link', { name: 'Open bank transactions' }),
  ).toBeVisible({ timeout: 30000 });
  await page.getByRole('link', { name: 'Open bank transactions' }).click();
  await expect(
    page.getByText('Fixture lunch', { exact: true }).first(),
  ).toBeVisible();
  await expect(page.getByText('-12.34', { exact: true }).first()).toBeVisible();
  await page.screenshot({ path: '/tmp/mt940-table.png', fullPage: true });
  await page.goto(new URL('/app/integrations', page.url()).href);
  await page
    .getByRole('region', { name: 'Your integrations' })
    .getByRole('link', { name: 'Bank statements' })
    .click();
  await page.getByRole('tab', { name: 'Run', exact: true }).click();
  await expect(page.locator('#mt940-file')).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Run', exact: true }),
  ).toHaveCount(0);
  await page.locator('#mt940-file').setInputFiles({
    name: 'synthetic.mt940',
    mimeType: 'text/plain',
    buffer: Buffer.from(statement),
  });
  await page
    .getByRole('button', { name: 'Preview import', exact: true })
    .click();
  await expect(
    page.getByText(/2 previously imported transactions skipped/),
  ).toBeVisible({ timeout: 30000 });
  await expect(
    page.getByRole('button', { name: 'Apply 0 changes' }),
  ).toBeDisabled();
  await page.screenshot({
    path: '/tmp/mt940-repeat-preview.png',
    fullPage: true,
  });
});
