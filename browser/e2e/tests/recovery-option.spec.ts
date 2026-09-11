import { managedTest as test, expect } from './deployment-fixtures';

// The portal is mocked on this origin; its dashboard must reach page.route
// rather than the app service worker's navigation fallback.
test.use({ serviceWorkers: 'block' });

test.beforeEach(({ browserDiagnostics }) => {
  browserDiagnostics.expect(
    'warning',
    /^Service Worker registration blocked by Playwright$/,
    'This spec disables the app worker so mocked portal navigation is intercepted.',
  );
});

// A portal session is not evidence that an encrypted recovery backup exists.
test('does not offer account recovery when the signed-in account has no backup', async ({
  page,
}) => {
  await page.route('**/api/me', route =>
    route.fulfill({ json: { email: 'no-backup@example.com' } }),
  );
  await page.route('**/api/recovery-secret', route =>
    route.fulfill({ status: 204 }),
  );
  const checked = page.waitForResponse(response =>
    response.url().endsWith('/api/recovery-secret'),
  );
  await page.goto(
    `${process.env.FRONTEND_URL || 'http://localhost:6747'}/app/welcome?next=did%3Aad%3Atest`,
  );
  await expect(page.getByLabel('Agent secret', { exact: true })).toBeVisible();
  await checked;
  await expect(
    page.getByRole('heading', { name: 'Unlock this drive' }),
  ).toBeVisible();
  await expect(
    page.getByText(/You’re signed in as no-backup@example.com/),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: /^Forgot it\? Restore from/ }),
  ).toHaveCount(0);
  await expect(
    page.getByRole('button', { name: 'Create account', exact: true }),
  ).toHaveCount(0);
  await page.route('**/dashboard', route =>
    route.fulfill({ contentType: 'text/html', body: '<h1>Portal drives</h1>' }),
  );
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await expect(
    page.getByRole('heading', { name: 'Portal drives' }),
  ).toBeVisible();
});

test('managed welcome goes to the portal instead of standalone onboarding', async ({
  page,
}) => {
  const welcomeFrames: string[] = [];
  await page.exposeFunction('reportStandaloneWelcome', () =>
    welcomeFrames.push('shown'),
  );
  await page.addInitScript(() => {
    new MutationObserver(() => {
      if (
        [...document.querySelectorAll('button')].some(button =>
          button.textContent?.includes('Try the live demo'),
        )
      ) {
        (
          window as unknown as { reportStandaloneWelcome: () => void }
        ).reportStandaloneWelcome();
      }
    }).observe(document, { childList: true, subtree: true });
  });
  await page.route('**/dashboard', route =>
    route.fulfill({ contentType: 'text/html', body: '<h1>Portal drives</h1>' }),
  );
  await page.goto(
    `${process.env.FRONTEND_URL || 'http://localhost:6747'}/app/welcome`,
  );
  await expect(
    page.getByRole('heading', { name: 'Portal drives' }),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Try the live demo' }),
  ).toHaveCount(0);
  expect(welcomeFrames).toEqual([]);
});
