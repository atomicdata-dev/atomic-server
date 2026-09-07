import { test, expect, type Page } from './fixtures';
import {
  before,
  createTableFromDialog,
  inDialog,
  reloadGrid,
  setGridCell,
  waitForGridInteractive,
} from './test-utils';

/**
 * A row action is a button on every row that writes one thing — the verb a
 * mini-app is mostly made of ("Watered", "+1", "Got it"). It is view
 * configuration, not code, so what is worth proving is that a configured button
 * arrives working, that pressing it commits, and that a person can add one.
 */

/** The grid row containing `text`. */
const row = (page: Page, text: string) =>
  page.getByRole('row').filter({ hasText: text });

/**
 * Creates a table from a template card. `openView` names the tab to switch to
 * first, for the templates whose default view is a board rather than a grid.
 */
async function createFromTemplate(
  page: Page,
  template: RegExp,
  name: string,
  openView?: string,
) {
  await createTableFromDialog(page, { template, name });

  if (openView) {
    await page.getByRole('tab', { name: openView }).click();
  }

  await expect(page.getByRole('grid')).toBeVisible();
  await waitForGridInteractive(page);
}

/** Types a value into one grid cell, addressed by its row and column index. */
async function setCell(
  page: Page,
  rowIndex: number,
  columnIndex: number,
  value: string,
) {
  await setGridCell(page, rowIndex, columnIndex, value);
}

/** The column headings, left to right. */
const headings = (page: Page) =>
  page.evaluate(() =>
    Array.from(document.querySelectorAll('[role="columnheader"]'))
      .slice(1)
      .map(el => (el.textContent ?? '').replace('Drag column', '').trim()),
  );

test.describe('row actions', () => {
  test.beforeEach(before);
  test.slow();

  test('Plant care ships a Watered button that stamps the date', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1800, height: 900 });
    await createFromTemplate(page, /Plant care/, 'Plants');

    // The template's action arrives as a column of its own.
    expect(await headings(page)).toContain('Watered');

    await setCell(page, 2, 2, 'Monstera');
    await reloadGrid(page);

    const plant = row(page, 'Monstera');
    const watered = plant.getByTestId('row-action-watered');

    // Nothing recorded yet, so the button does not read as done.
    await expect(watered).toHaveAttribute('data-active', 'false');

    await watered.click();

    // The press is a commit on that row: the date column fills in, and the
    // button now reads as done — which is what makes it a state readout as well
    // as a control.
    await expect(watered).toHaveAttribute('data-active', 'true', {
      timeout: 15_000,
    });
    // And the column computed from that date follows, without a reload: a
    // computed cell subscribes to the properties it derives from.
    await expect(plant.getByTestId('derived-thirsty-for')).toHaveText('today', {
      timeout: 15_000,
    });

    await reloadGrid(page);
    await expect(
      row(page, 'Monstera').getByTestId('row-action-watered'),
    ).toHaveAttribute('data-active', 'true');
    await expect(
      row(page, 'Monstera').getByTestId('derived-thirsty-for'),
    ).toHaveText('today');
  });

  test('Inventory counts up and down without opening a cell', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1800, height: 900 });
    await createFromTemplate(page, /Inventory/, 'Stockroom');

    await setCell(page, 2, 2, 'Bolts');
    // Quantity is the third column of the template's order.
    await setCell(page, 2, 4, '3');
    await reloadGrid(page);

    const bolts = row(page, 'Bolts');
    await expect(bolts).toContainText('3');

    await bolts.getByTestId('row-action-plus').click();
    await expect(bolts).toContainText('4', { timeout: 15_000 });

    // The same verb with a negative step is the "one fewer" button — no second
    // concept needed.
    await bolts.getByTestId('row-action-minus').click();
    await expect(bolts).toContainText('3', { timeout: 15_000 });

    // Value block: the totals footer sums the quantity the buttons changed.
    // 30s: the total needs an aggregate read to get through the ClientDb
    // worker, and post-reload that queue sits behind the re-drain's write
    // storm for 15s+ on a loaded runner (measured ~18.5s in the instrumented
    // CI runs). Tracked as the OPFS write-amplification issue — when write
    // count drops, this budget can too.
    await expect(page.getByTestId('table-totals')).toContainText('3', {
      timeout: 30_000,
    });
  });

  test('a person can add an action, and it works and persists', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1800, height: 900 });
    // Grocery list has a checkbox column, which is what `toggle` writes. Its
    // board is the default view, so open the list.
    await createFromTemplate(page, /Grocery list/, 'Shopping', 'List');

    await setCell(page, 2, 2, 'Milk');
    await reloadGrid(page);

    // The template already ships one toggle; add a second, different action
    // through the UI to prove the dialog writes what the template writes.
    await page.getByRole('button', { name: 'Add column' }).click();
    await page.getByTestId('menu-item-action').click();

    await inDialog(page, async () => {
      await page.getByTestId('action-config-kind').selectOption('increment');
      await page
        .getByTestId('action-config-property')
        .selectOption({ label: 'Quantity' });
      await page.getByTestId('action-config-value').fill('2');
      await page.getByTestId('action-config-label').fill('Two more');
      await page.getByTestId('action-config-save').click();
    });

    await expect(
      page.getByRole('columnheader', { name: /Two more/ }),
    ).toBeVisible({ timeout: 15_000 });

    const milk = row(page, 'Milk');
    await milk.getByTestId('row-action-two-more').click();
    await expect(milk).toContainText('2', { timeout: 15_000 });

    // Configuration lives on the View, so it comes back. Column headers
    // hydrate from the View resource after the grid mounts — a one-shot
    // `headings()` read right after `reloadGrid`'s 500ms settle often saw
    // `[]` under CI load even though the action column appeared a moment
    // later.
    await reloadGrid(page);
    await expect
      .poll(() => headings(page), { timeout: 15_000 })
      .toContain('Two more');
    await row(page, 'Milk').getByTestId('row-action-two-more').click();
    await expect(row(page, 'Milk')).toContainText('4', { timeout: 15_000 });
  });

  test('the template toggle flips a checkbox on and off', async ({ page }) => {
    await page.setViewportSize({ width: 1800, height: 900 });
    await createFromTemplate(page, /Grocery list/, 'Shopping toggles', 'List');

    await setCell(page, 2, 2, 'Bread');
    await reloadGrid(page);

    const bread = row(page, 'Bread');
    const gotIt = bread.getByTestId('row-action-got-it');

    await expect(gotIt).toHaveAttribute('data-active', 'false');
    await gotIt.click();
    await expect(gotIt).toHaveAttribute('data-active', 'true', {
      timeout: 15_000,
    });

    // Pressing again clears it rather than writing `false`, so an un-ticked row
    // reads the same as one never ticked.
    await gotIt.click();
    await expect(gotIt).toHaveAttribute('data-active', 'false', {
      timeout: 15_000,
    });
  });
});
