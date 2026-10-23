import { test, expect } from './fixtures';
import { FRONTEND_URL, nodeReachableServerUrl, SERVER_URL } from './test-utils';

test('a fresh Mac install can start account recovery before it has an agent', async ({
  page,
}) => {
  const embeddedOrigin = 'http://localhost:9883';
  const realOrigin = nodeReachableServerUrl(SERVER_URL);

  if (realOrigin !== embeddedOrigin) {
    await page.route(`${embeddedOrigin}/**`, async route => {
      const url = route.request().url().replace(embeddedOrigin, realOrigin);
      const response = await route.fetch({ url });
      await route.fulfill({ response });
    });
    // The HTTP proxy above cannot carry a socket, and nothing here needs
    // live updates. Accept it and stay silent, so the app sees no failed
    // connection instead of retrying an unreachable port.
    await page.routeWebSocket(
      `${embeddedOrigin.replace('http', 'ws')}/ws`,
      () => {},
    );
  }

  await page.route('http://localhost:9885/**', async route => {
    const url = route
      .request()
      .url()
      .replace('http://localhost:9885', realOrigin);
    const response = await route.fetch({ url });
    await route.fulfill({ response });
  });

  await page.addInitScript(portalUrl => {
    const w = window as unknown as Window & {
      __TAURI_INTERNALS__: object;
      __ATOMIC_MANAGED__: { portalUrl: string };
    };
    w.__TAURI_INTERNALS__ = {};
    w.__ATOMIC_MANAGED__ = { portalUrl };
  }, FRONTEND_URL);
  await page.route('**/api/me', route => route.fulfill({ status: 204 }));

  await page.goto(`${FRONTEND_URL}/app/welcome`);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  // No agent and no session: the sign-in step itself offers the account's
  // options, each finished in the system browser, so recovery starts here.
  // The agent secret is one of them, as on the portal, not a field of its own.
  await expect(page.locator('[data-test="secret-sign-in"]')).toBeVisible();
  await expect(page.getByLabel('Agent secret', { exact: true })).toHaveCount(0);
  await expect(page.getByLabel('Email', { exact: true })).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Email me a link' }),
  ).toBeVisible();
});
