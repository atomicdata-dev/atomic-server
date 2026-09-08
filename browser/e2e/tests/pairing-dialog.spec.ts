import { test, expect, type Page } from './fixtures';
import {
  before,
  FRONTEND_URL,
  nodeReachableServerUrl,
  SERVER_URL,
  smoke,
} from './test-utils';

/**
 * Taking someone else's pairing code — the paste path, and what the dialog
 * tells you when it works and when it doesn't.
 *
 * This surface is gated on `isRunningInTauri()`, because dialling a peer needs
 * a node and a browser tab is not one. So it never renders in a normal e2e run
 * and had no coverage at all. Faking the Tauri global is enough to reach it:
 * `isRunningInTauri()` only checks for `window.__TAURI_INTERNALS__`. The page
 * then also resolves its embedded server as `localhost:9883`, so
 * `pretendToBeTheApp` proxies that origin to `SERVER_URL` when they differ
 * (dagger CI). Nothing here calls `invoke`, so an empty stand-in object is
 * sufficient.
 *
 * `/iroh-sync` is intercepted rather than dialled for real: what is under test
 * is how the UI reports an outcome, and the endpoint itself is covered against
 * a real second node in `server/tests/it/iroh_pairing.rs`.
 *
 * The second block covers the other half of the same gate: the cards a device
 * shows for peers it has already paired with.
 */

const NODE = `did:ad:node:${'a'.repeat(64)}`;
const VALID_CODE = `atomic://pair?v=1&node=${NODE}&drives=*`;

/**
 * Make the page believe it is the desktop/mobile app.
 *
 * `isRunningInTauri()` only checks for `window.__TAURI_INTERNALS__`, but once
 * that is set the app also hardcodes its embedded server as
 * `http://localhost:9883` (`getLocalServerOrigin`). Locally that is the real
 * server; in dagger CI the server is `atomic.localhost` / `atomic`. Without a
 * proxy, `useOwnNodeDid` never gets a node id and the paste form stays hidden
 * behind `pairNodeId && …`.
 */
async function pretendToBeTheApp(page: Page) {
  const embeddedOrigin = 'http://localhost:9883';
  // Fetch from Node via the service-binding host — not SERVER_URL's
  // `atomic.localhost`, which only Chromium can resolve in dagger.
  const realOrigin = nodeReachableServerUrl(SERVER_URL);

  if (realOrigin !== embeddedOrigin) {
    await page.route(`${embeddedOrigin}/**`, async route => {
      const rewritten = route
        .request()
        .url()
        .replace(embeddedOrigin, realOrigin);
      const response = await route.fetch({ url: rewritten });
      await route.fulfill({ response });
    });
  }

  await page.addInitScript(() => {
    (
      window as unknown as { __TAURI_INTERNALS__: unknown }
    ).__TAURI_INTERNALS__ = {};
  });
}

/**
 * Stub the pairing request. Returns a counter so a test can assert the request
 * was never made — the difference between "rejected the code" and "asked the
 * node and was told no".
 */
async function stubIrohSync(page: Page, body: unknown) {
  const calls = { count: 0 };

  await page.route('**/iroh-sync', async route => {
    calls.count++;
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(body),
    });
  });

  return calls;
}

async function gotoSync(page: Page) {
  await page.goto(`${FRONTEND_URL}/app/sync`);
  await expect(
    page.getByRole('heading', { name: 'Sync', exact: true }),
  ).toBeVisible();
}

const codeInput = (page: Page) =>
  page.getByPlaceholder('Paste a pairing code or did:ad:node:…');

async function pasteCode(page: Page, code: string) {
  await codeInput(page).fill(code);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
}

test.describe('pairing by pasting a code', () => {
  test.beforeEach(before);

  test('the paste form is offered on a device, not in a browser tab', async ({
    page,
  }) => {
    // Browser first: dialling needs a node, so the form must not be there.
    await gotoSync(page);
    await expect(codeInput(page)).toHaveCount(0);

    await pretendToBeTheApp(page);
    await gotoSync(page);
    await expect(codeInput(page)).toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Connect', exact: true }),
    ).toBeVisible();
  });

  test('a malformed code is refused without dialling anyone', async ({
    page,
  }) => {
    await pretendToBeTheApp(page);
    const calls = await stubIrohSync(page, { count: 0 });
    await gotoSync(page);

    // Shaped like a pairing URI, so it reaches the flow, but the node id is
    // not 64 hex characters. Note that input which is not a URI at all is
    // dropped earlier still, by `PairingLinkHandler`, and reports nothing.
    await pasteCode(
      page,
      `atomic://pair?v=1&node=did:ad:node:tooshort&drives=*`,
    );

    await expect(
      page.getByRole('heading', { name: 'Pairing device' }),
    ).toBeVisible();
    await expect(page.getByText('Could not connect')).toBeVisible();
    // A message, not a blank failure — the user has to know what to fix.
    await expect(page.getByRole('alert')).not.toBeEmpty();

    expect(calls.count).toBe(0);
  });

  test('a refusal from the node is shown verbatim', async ({ page }) => {
    await pretendToBeTheApp(page);
    await stubIrohSync(page, { error: 'That device is offline' });
    await gotoSync(page);

    await pasteCode(page, VALID_CODE);

    await expect(page.getByRole('alert')).toHaveText('That device is offline');
    // Retrying is the obvious next move for a transient failure.
    await expect(
      page.getByRole('button', { name: 'Try again', exact: true }),
    ).toBeVisible();
  });

  test(
    'a successful pairing reports what synced, and with whom',
    smoke,
    async ({ page }) => {
      await pretendToBeTheApp(page);
      const calls = await stubIrohSync(page, {
        count: 3,
        peerName: 'Joep’s phone',
      });
      await gotoSync(page);

      await pasteCode(page, VALID_CODE);

      await expect(
        page.getByText('Synced 3 resources with Joep’s phone'),
      ).toBeVisible();
      expect(calls.count).toBe(1);
    },
  );

  test('the paired device is remembered for next time', async ({ page }) => {
    await pretendToBeTheApp(page);
    await stubIrohSync(page, { count: 1, peerName: 'Tablet' });
    await gotoSync(page);

    await pasteCode(page, VALID_CODE);
    await expect(page.getByText(/Synced 1 resource with Tablet/)).toBeVisible();

    // Recording the peer is what lets a later sync or auto-connect reach it
    // without the user finding the code again.
    const stored = await page.evaluate(() =>
      JSON.parse(localStorage.getItem('atomic-peers') ?? '[]'),
    );
    expect(stored).toContainEqual(
      expect.objectContaining({ nodeId: NODE, label: 'Tablet' }),
    );
  });
});

test.describe('paired devices on the sync page', () => {
  test.beforeEach(before);

  /** Seed the peer list the app auto-dials from, before the page loads. */
  async function withStoredPeers(
    page: Page,
    peers: Array<{ nodeId: string; label: string }>,
  ) {
    await page.addInitScript(stored => {
      localStorage.setItem('atomic-peers', JSON.stringify(stored));
    }, peers);
  }

  test('a paired device is listed with a way to forget it', async ({
    page,
  }) => {
    await pretendToBeTheApp(page);
    await withStoredPeers(page, [{ nodeId: NODE, label: 'Joep’s phone' }]);
    await gotoSync(page);

    await expect(page.getByText('Joep’s phone')).toBeVisible();
    await expect(page.getByText('Paired', { exact: true })).toBeVisible();
    // Unpairing has to be reachable from here: this list is what the device
    // auto-dials, so there is nowhere else to remove an entry from.
    await expect(
      page.getByRole('button', { name: 'Remove', exact: true }),
    ).toBeVisible();
  });

  test('a stored entry with a malformed node id is not shown', async ({
    page,
  }) => {
    await pretendToBeTheApp(page);
    await withStoredPeers(page, [
      { nodeId: NODE, label: 'Real device' },
      { nodeId: 'did:ad:node:tooshort', label: 'Corrupt entry' },
    ]);
    await gotoSync(page);

    await expect(page.getByText('Real device')).toBeVisible();
    // A node id that cannot be dialled is worse than absent: it would render a
    // device the user thinks is paired and which can never sync.
    await expect(page.getByText('Corrupt entry')).toHaveCount(0);
  });
});
