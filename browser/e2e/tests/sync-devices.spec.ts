import { test, expect, type Page } from './fixtures';
import {
  before,
  FRONTEND_URL,
  SERVER_URL,
  nodeReachableServerUrl,
} from './test-utils';

/**
 * The Sync page's device-facing surface: the pairing code a user scans, and
 * the Connect a device section they add an always-on device with.
 *
 * `sync.spec.ts` covers data actually syncing. This file covers the parts a
 * user touches to *set that up*, which had no coverage at all — the pairing
 * code in particular is the one string a second device has to act on, and
 * nothing checked it was even well-formed.
 *
 * Paired-peer cards and taking a pairing code are gated on `isRunningInTauri()`
 * and cannot work in a browser run, so they are out of scope here; they need
 * a desktop harness. The browser answers a pasted code with a message instead.
 */

const PAIRING_CODE = /^atomic:node:[0-9a-f]{64}\?/i;

async function gotoSync(page: Page) {
  await page.goto(`${FRONTEND_URL}/app/sync`);
  await expect(
    page.getByRole('heading', { name: 'Sync', exact: true }),
  ).toBeVisible();
}

test.describe('sync page devices', () => {
  test.beforeEach(before);

  test('an unenrolled drive does not inherit another drive cloud status', async ({
    page,
  }) => {
    let managedInfoRequests = 0;
    let accountConnected = false;
    await page.route('**/server', async route => {
      const response = await route.fetch({
        url: nodeReachableServerUrl(route.request().url()),
      });
      const body = await response.json();
      managedInfoRequests += 1;
      await route.fulfill({
        json: {
          ...body,
          'https://atomicdata.dev/properties/server/managed': true,
          'https://atomicdata.dev/properties/server/portalUrl':
            'http://localhost:49237',
        },
      });
    });
    // The node holds nothing for this drive: a drive that finished syncing
    // with a managed node and has data there counts as hosted for everyone,
    // so any data here would make the Upgrade row race the real sync.
    await page.route('**/drive-usage?**', route =>
      route.fulfill({
        json: { resourceCount: 0, blobBytes: 0, loroBytes: 0 },
      }),
    );
    await page.route('**/api/**', route => {
      const path = new URL(route.request().url()).pathname;

      return path === '/api/me'
        ? accountConnected
          ? route.fulfill({ json: { email: 'sync-account@example.com' } })
          : route.fulfill({ status: 204 })
        : route.fulfill({ json: [] });
    });
    await gotoSync(page);
    await expect.poll(() => managedInfoRequests).toBeGreaterThan(0);
    await page.evaluate(() => {
      window.store.finishDriveSync('did:ad:other-work-drive', 28, Date.now());
    });
    const cloud = page.getByTestId('cloud-server-row');
    await expect(cloud).toBeVisible();
    await expect(cloud).not.toContainText('In sync');
    await expect(cloud).not.toContainText('Synced');
    await expect(cloud).not.toContainText('Cloud Server is on');
    const recovery = page.getByTestId('recovery-row');
    await expect(recovery).toContainText('Sign in to your');
    await expect(recovery).not.toContainText('Not set up');
    await expect(page.locator('body')).not.toContainText('[i18n-404:');
    accountConnected = true;
    await page.evaluate(() => window.dispatchEvent(new Event('focus')));
    // Signed in, the account header names who; the recovery row only
    // returns when recovery needs you.
    await expect(page.getByTestId('provider-account')).toContainText(
      'sync-account@example.com',
    );
    await expect(
      cloud.getByRole('button', {
        name: 'Upgrade to Cloud Server',
        exact: true,
      }),
    ).toBeVisible();
    await expect(page.getByTestId('link-provider-panel')).not.toBeVisible();
  });

  test('the pairing code on screen is a routable envelope', async ({
    page,
  }) => {
    await gotoSync(page);

    // Rendered only once the server has reported a node identifier.
    const code = page.locator('code', { hasText: PAIRING_CODE });
    await expect(code).toBeVisible();

    const uri = (await code.textContent())?.trim() ?? '';
    const params = new URLSearchParams(uri.split('?')[1]);

    // The node is the URI subject. The query supplies its routing hints.
    expect(params.get('v')).toBe('1');
    expect(uri.split('?')[0]).toMatch(/^atomic:node:[0-9a-f]{64}$/i);
    expect(params.getAll('drives').length).toBeGreaterThan(0);
  });

  test('the code is safe to show — it carries no secret', async ({ page }) => {
    await gotoSync(page);

    const uri =
      (
        await page.locator('code', { hasText: PAIRING_CODE }).textContent()
      )?.trim() ?? '';

    // A pairing code is routing only. Anything key-shaped in here would mean
    // a printed or photographed code could hand over the account.
    expect(uri).not.toMatch(/secret|privateKey|private_key/i);
    // Only the documented fields; `drives` may repeat. `url` is an optional
    // LAN/WS fast-path hint — present when the server isn't localhost (e.g.
    // dagger's `atomic.localhost`), absent for a loopback server.
    const keys = new Set([...new URLSearchParams(uri.split('?')[1]).keys()]);
    expect([...keys].sort()).toEqual(
      keys.has('url') ? ['drives', 'url', 'v'] : ['drives', 'v'],
    );
  });

  test('copying the pairing code puts that exact code on the clipboard', async ({
    page,
    context,
  }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await gotoSync(page);

    const uri =
      (
        await page.locator('code', { hasText: PAIRING_CODE }).textContent()
      )?.trim() ?? '';

    await page.getByRole('button', { name: 'Copy', exact: true }).click();
    await expect(page.getByText('Pairing code copied.')).toBeVisible();

    const clipboard = await page.evaluate(() => navigator.clipboard.readText());
    expect(clipboard).toBe(uri);
  });

  test('adding a device requires an address before it will submit', async ({
    page,
  }) => {
    await gotoSync(page);

    // One section, always there: no button to reveal it first.
    await expect(
      page.getByRole('heading', { name: 'Connect a device', exact: true }),
    ).toBeVisible();

    const address = page.getByPlaceholder('Code or server address');
    await expect(address).toBeVisible();

    const connect = page.getByRole('button', { name: 'Connect', exact: true });
    await expect(connect).toBeDisabled();

    await address.fill('example.test:9883');
    await expect(connect).toBeEnabled();

    // Clearing the box must not leave a half-added device behind.
    await address.fill('');
    await expect(connect).toBeDisabled();
    await expect(page.getByText('example.test:9883')).toHaveCount(0);
  });

  test('a pasted pairing code in a browser tab says where it can be entered', async ({
    page,
  }) => {
    await gotoSync(page);

    await page
      .getByPlaceholder('Code or server address')
      .fill(`atomic:node:${'a'.repeat(64)}?v=1`);
    await page.getByRole('button', { name: 'Connect', exact: true }).click();

    await expect(page.getByTestId('connect-device-message')).toContainText(
      'device that runs the app',
    );
  });

  test('the devices section lists the server this drive syncs with', async ({
    page,
  }) => {
    await gotoSync(page);

    await expect(
      page.getByRole('heading', { name: 'Devices', exact: true }),
    ).toBeVisible();

    // The dev drive is created against whatever server the suite was pointed
    // at, so that connection is the one thing guaranteed to be listed. Derived
    // from SERVER_URL rather than hardcoded: the port is configurable (the
    // suite runs against 9885 when the app is, see the README), and a literal
    // 9883 here passes on the default and fails everywhere else for a reason
    // that names neither port.
    const host = new URL(SERVER_URL).host;
    await expect(page.getByText(host).first()).toBeVisible();
  });
});
