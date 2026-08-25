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

    // And the frame is the page. An iframe never grows to fit its document,
    // so a box shorter than the page does not scroll — it clips the app and
    // leaves dead space underneath. Only the container's own padding should
    // sit between the bottom of the frame and the bottom of the page.
    const pageBox = (await main.boundingBox())!;
    const frameBox = (await main.locator('iframe[title="App"]').boundingBox())!;
    expect(frameBox.y + frameBox.height).toBeGreaterThan(
      pageBox.y + pageBox.height - 48,
    );

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

  test('an app can be a view on a table, beside the table view', async ({
    page,
  }) => {
    const main = page.getByRole('main');

    await page.getByRole('button', { name: 'More' }).click();
    await page.getByPlaceholder(/filter/i).fill('app');
    await page.locator('[data-testid="menu-item-new-app"]').click();
    await expect(main.locator('iframe[title="App"]')).toBeVisible();

    // Open the app's own table and add the app as a second way to see it.
    const sidebar = page.getByRole('navigation').last();
    await sidebar.getByRole('button', { name: 'Expand folder' }).last().click();
    await sidebar.getByRole('button', { name: 'Items', exact: true }).click();
    await expect(main.getByRole('tablist')).toBeVisible();

    await main.getByRole('button', { name: 'Add view' }).click();
    await page.getByRole('menuitem', { name: 'New app' }).click();

    // The app now renders these rows, in a tab of its own...
    await expect(main.locator('iframe[title="App"]')).toBeVisible();

    // ...and the table is still right there. Adding a way to look at rows
    // must never take one away.
    await main.getByRole('tab', { name: 'Table' }).click();
    await expect(main.locator('iframe[title="App"]')).toBeHidden();
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

  test('an app that breaks says so, and offers to have it fixed', async ({
    page,
  }) => {
    const main = page.getByRole('main');

    await page.getByRole('button', { name: 'More' }).click();
    await page.getByPlaceholder(/filter/i).fill('app');
    await page.locator('[data-testid="menu-item-new-app"]').click();
    await expect(main.locator('iframe[title="App"]')).toBeVisible();

    // Break it. The frame is null-origin, so its console belongs to nobody —
    // without a report crossing the boundary this is a blank panel and the
    // person who could fix it never learns there was anything to fix.
    await setAppSource(
      page,
      'export function view() { throw new Error("kaboom"); }',
    );
    await page.reload();

    const alert = main.getByRole('alert');
    await expect(alert).toContainText('kaboom');

    // The whole point of reporting it: somewhere to go next.
    await expect(alert.getByRole('button', { name: 'Fix it' })).toBeVisible();
  });
});

/**
 * Replaces the source of the app on screen, through `window.store`.
 *
 * The entry point is a child of the app and the source property is drive-local
 * with no fixed subject, so both are found by value rather than by a path this
 * test would then have to keep up with.
 */
async function setAppSource(
  page: import('@playwright/test').Page,
  source: string,
) {
  await page.evaluate(async (next: string) => {
    const store = (
      window as unknown as {
        store: {
          getResource(s: string): Promise<{
            getPropVals(): Record<string, unknown>;
            set(p: string, v: unknown): Promise<void>;
            save(): Promise<unknown>;
          }>;
        };
      }
    ).store;

    const subject = decodeURIComponent(
      new URL(location.href).searchParams.get('subject')!,
    );
    const app = await store.getResource(subject);

    for (const value of Object.values(app.getPropVals())) {
      if (typeof value !== 'string' || !value.includes(':')) continue;

      const child = await store.getResource(value).catch(() => undefined);

      if (!child) continue;

      const sourceProp = Object.entries(child.getPropVals()).find(
        ([, v]) =>
          typeof v === 'string' && v.includes('export async function view'),
      )?.[0];

      if (!sourceProp) continue;

      await child.set(sourceProp, next);
      await child.save();

      return;
    }

    throw new Error('could not find the app’s entry point');
  }, source);
}
