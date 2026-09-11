import { mockManagedPortal } from './managed-test-utils';
import { test, expect } from '@playwright/test';
import { devDrive, FRONTEND_URL } from './test-utils';

test('explains missing passkey support without offering a broken setup action', async ({
  page,
}) => {
  await devDrive(page);
  await mockManagedPortal(page);
  const agent = await page.evaluate(
    () =>
      (
        window as unknown as { store: { getAgent(): { subject: string } } }
      ).store.getAgent().subject,
  );
  await page.addInitScript(() => {
    Object.defineProperty(window, 'PublicKeyCredential', {
      value: undefined,
      configurable: true,
    });
  });
  await page.route('**/api/me', route =>
    route.fulfill({ json: { email: 'passkey-test@example.com' } }),
  );
  await page.route('**/api/recovery-secret', route =>
    route.fulfill({
      json: {
        agent_subject: agent,
        format_version: 2,
        encrypted_secret: 'test',
        wrappers: [{ wrapper_type: 'recovery-code', kdf_params: {} }],
      },
    }),
  );
  await page.goto(`${FRONTEND_URL}/app/agent`);
  await expect(
    page.getByText('This browser does not expose passkey support.', {
      exact: false,
    }),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Add a passkey', exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole('button', { name: 'Use recovery code', exact: true }),
  ).toBeEnabled();
});
