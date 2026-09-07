import { test, expect } from './fixtures';
import {
  FRONTEND_URL,
  editableTitle,
  setGridCell,
  waitForClientDbFlush,
} from './test-utils';

/**
 * Offline-first table test.
 *
 * Runs in the normal (server-up) environment: instead of requiring
 * atomic-server to be stopped, it sets up the dev drive online and then
 * DISCONNECTS the client via the Sync page. `store.disconnect()` persists the
 * offline state across a reload (localStorage `ws-disconnected`), so the reload
 * stays offline and the table + row must come back purely from the client-side
 * WASM DB / OPFS.
 */
test.describe('offline tables', () => {
  test('create table + row while disconnected and persist across reload', async ({
    page,
  }) => {
    test.slow();

    // 1. Set up the dev drive (online).
    await page.goto(`${FRONTEND_URL}/app/dev-drive`, {
      waitUntil: 'domcontentloaded',
    });
    await page.waitForFunction(() => window.store.getClientDb()?.isReady, {
      timeout: 30000,
    });
    await page.waitForURL(/did(?:%3A|:)ad(?:%3A|:)/, { timeout: 30000 });
    await expect(page.getByTestId('current-drive-title')).toBeVisible({
      timeout: 15000,
    });

    // 2. Go to the Sync page and disconnect from the server.
    await page
      .getByTestId('sidebar')
      .getByRole('link', { name: 'Sync' })
      .click();
    await page.getByRole('button', { name: 'Disconnect' }).click();
    await expect
      .poll(() =>
        page.evaluate(() => window.store.getSyncStatus().serverConnected),
      )
      .toBe(false);

    // 3. Create a table — offline.
    await page
      .getByTestId('sidebar')
      .getByRole('button', { name: 'New Table' })
      .click();
    const tableNameInput = page.getByPlaceholder('New Table');
    await expect(tableNameInput).toBeVisible({ timeout: 5000 });
    await tableNameInput.fill('My Offline Table');
    await page.locator('dialog[open] button:has-text("Create")').click();
    await expect(editableTitle(page)).toBeVisible({ timeout: 15000 });
    await expect(
      page.getByTestId('sidebar').getByText('My Offline Table'),
    ).toBeVisible({ timeout: 10000 });

    // 4. Fill the first row (auto-created with the table) — offline.
    //    Double-click: first click sets Visual mode, second enters Edit mode.
    const nameCell = page.locator('[aria-rowindex="2"] [aria-colindex="2"]');
    await expect(nameCell).toBeVisible({ timeout: 10000 });
    await setGridCell(page, 2, 2, 'Test Row 1');
    await waitForClientDbFlush(page);

    await expect(
      page.getByRole('gridcell', { name: 'Test Row 1' }),
    ).toBeVisible();

    // 5. Reload — still offline (disconnect persists) — and verify the table
    //    and row come back from OPFS.
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.store?.getClientDb()?.isReady, {
      timeout: 30000,
    });
    await expect
      .poll(() =>
        page.evaluate(() => window.store?.getSyncStatus().serverConnected),
      )
      .toBe(false);

    await expect(
      page.getByTestId('editable-title').getByText('My Offline Table'),
    ).toBeVisible({ timeout: 15000 });

    // Header + 1 data row + trailing new row.
    const rows = page.locator('[aria-rowindex]');
    await expect(rows).toHaveCount(3, { timeout: 15000 });
  });
});
