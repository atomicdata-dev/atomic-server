import { test, expect } from './fixtures';
import { before, FRONTEND_URL } from './test-utils';

test.beforeEach(before);

test('an emailed invite cannot change the signing server before origin confirmation', async ({
  page,
}) => {
  const original = await page.evaluate(() => window.store!.getServerUrl());
  const requests: string[] = [];
  const foreign = 'http://untrusted.localhost:19099';
  await page.route(`${foreign}/**`, async route => {
    requests.push(route.request().url());
    await route.fulfill({ status: 403, body: 'Test server: no access' });
  });
  const token = Buffer.from('{}').toString('base64');
  await page.goto(
    `${FRONTEND_URL}/app/invite?${new URLSearchParams({ token, server: foreign, accept: 'true' })}`,
  );
  await expect(
    page.getByRole('heading', {
      name: 'Open an invitation from another server?',
    }),
  ).toBeVisible();
  expect(await page.evaluate(() => window.store!.getServerUrl())).toBe(
    original,
  );
  expect(
    await page.evaluate(() => window.store!.getAgent()?.subject),
  ).toBeTruthy();
  expect(requests).toEqual([]);
  await page.reload();
  await expect(
    page.getByRole('button', { name: 'Continue to invitation' }),
  ).toBeVisible();
  expect(await page.evaluate(() => window.store!.getServerUrl())).toBe(
    original,
  );
  expect(requests).toEqual([]);
  await expect(page.locator('#boot-splash')).toBeHidden({ timeout: 15_000 });
  await page
    .getByRole('heading', { name: 'Open an invitation from another server?' })
    .locator('..')
    .screenshot({ path: '/tmp/critic-invite-origin.png' });
});

test('onboarding checks storage before showing account controls and keeps feedback available', async ({
  page,
}) => {
  await page.evaluate(() => {
    // Simulate the real ClientDb reporting a denied initialization, without
    // breaking the test account's database or depending on private-mode policy.
    const db = window.store!.getClientDb()!;
    const denied = new Proxy(db, {
      get(target, property) {
        if (property === 'waitForInit' || property === 'waitForReady') {
          return async () => false;
        }

        if (property === 'isReady') return false;
        if (property === 'initError') return new Error('Storage denied');
        // Preserve the database interface for saves already in flight from
        // the fixture. This test changes the onboarding readiness result.
        const value = Reflect.get(target, property, target);

        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    window.store!.getClientDb = () => denied;
    window.history.pushState({}, '', '/app/welcome');
    window.dispatchEvent(new PopStateEvent('popstate'));
  });
  await expect(
    page.getByRole('heading', {
      name: 'This browser could not open local storage',
    }),
  ).toBeVisible();
  await expect(
    page.getByText('Open this link in a non-private browser window', {
      exact: false,
    }),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Create account', exact: true }),
  ).toHaveCount(0);
  await page.getByRole('button', { name: 'Feedback', exact: true }).click();
  await expect(
    page.getByRole('heading', { name: 'Send feedback' }),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Close', exact: true }).click();
  await expect(
    page.getByRole('button', { name: 'Reload and try again' }),
  ).toBeVisible();
});

test('malformed invites still offer feedback', async ({ page }) => {
  await page.goto(`${FRONTEND_URL}/app/invite`);
  await expect(page.getByText('No invite token provided.')).toBeVisible();
  await page.getByRole('button', { name: 'Feedback', exact: true }).click();
  await expect(
    page.getByRole('heading', { name: 'Send feedback' }),
  ).toBeVisible();
});
