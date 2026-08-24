import { test, expect } from '@playwright/test';
import { before } from './test-utils';

/**
 * The one thing about apps that only a browser can answer.
 *
 * Everything underneath has cheaper tests: the token's scope and expiry, the
 * subtree rule, what `createApp` builds, that a write is signed by the app and
 * refused outside it — all unit or handler tests. What none of them can reach
 * is whether a null-origin iframe actually loads the module the server served,
 * renders it, and can talk back through postMessage well enough to write.
 *
 * So this walks exactly that: make an app, open it, click the thing, see the
 * data. If this passes, the whole chain is connected.
 */
test.describe('apps', () => {
  test.beforeEach(before);

  test('an app renders in its frame and writes its own data', async ({
    page,
  }) => {
    const main = page.getByRole('main');

    // `New app` is search-only: it creates the drive's plugin schema on first
    // use, so it stays out of the default listing.
    await page.getByRole('button', { name: 'More' }).click();
    await page.getByPlaceholder(/filter/i).fill('app');
    await page.locator('[data-testid="menu-item-new-app"]').click();

    // An app page is the app: no chrome of its own, just the frame.
    await expect(main.locator('iframe[title="App"]')).toBeVisible();

    // Null-origin, so Playwright reaches it as a frame rather than through
    // the parent's DOM — which is the isolation doing its job.
    const app = page.frameLocator('iframe[title="App"]');

    await expect(app.getByRole('heading', { name: 'New app' })).toBeVisible();

    const add = app.getByRole('button', { name: 'Add an item' });
    await expect(add).toBeVisible();

    // The click is the whole chain: the app's code calls store.newResource,
    // that crosses postMessage to the host, the host asks the server to write
    // as the app, and the app re-reads what landed.
    await add.click();
    await expect(app.getByRole('listitem').first()).toBeVisible();

    await add.click();
    await expect(app.getByRole('listitem')).toHaveCount(2);
  });

  test('rows an app adds are in its table, editable without the app', async ({
    page,
  }) => {
    const main = page.getByRole('main');

    await page.getByRole('button', { name: 'More' }).click();
    await page.getByPlaceholder(/filter/i).fill('app');
    await page.locator('[data-testid="menu-item-new-app"]').click();
    await expect(main.locator('iframe[title="App"]')).toBeVisible();

    const app = page.frameLocator('iframe[title="App"]');
    await app.getByRole('button', { name: 'Add an item' }).click();
    await expect(app.getByRole('listitem')).toHaveCount(1);

    // The app's rows are a table's rows. Opening that table gives the full
    // table UI — which is the point of not having the app draw a list:
    // sorting, filtering and editing come from the table, not from the app.
    const sidebar = page.getByRole('navigation').last();
    await sidebar.getByRole('button', { name: 'Expand folder' }).last().click();
    await sidebar.getByRole('button', { name: 'Items', exact: true }).click();

    // The table renders the row the app made, with the table's own UI around
    // it — nothing the app implemented.
    await expect(main.getByText('Item 1')).toBeVisible();
  });

  test('an app survives a reload, because its data is in the drive', async ({
    page,
  }) => {
    const main = page.getByRole('main');

    await page.getByRole('button', { name: 'More' }).click();
    await page.getByPlaceholder(/filter/i).fill('app');
    await page.locator('[data-testid="menu-item-new-app"]').click();
    await expect(main.locator('iframe[title="App"]')).toBeVisible();

    const app = page.frameLocator('iframe[title="App"]');
    await app.getByRole('button', { name: 'Add an item' }).click();
    await expect(app.getByRole('listitem')).toHaveCount(1);

    // Atomic is the persistence layer: nothing about the app is in the page.
    await page.reload();

    const reopened = page.frameLocator('iframe[title="App"]');
    await expect(reopened.getByRole('listitem')).toHaveCount(1);
  });
});
