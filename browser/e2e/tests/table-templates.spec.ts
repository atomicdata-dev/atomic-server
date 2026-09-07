import { test, expect, type Page } from './fixtures';
import {
  before,
  createTableFromDialog,
  newResource,
  reloadGrid,
  setGridCell,
  waitForGridInteractive,
  waitForRowsMaterialized,
} from './test-utils';

/**
 * The template catalogue, exercised as a user meets it: pick a starting point,
 * get a working mini-app. Each of these tables is configuration only — no
 * template ships a renderer — so what is worth proving end to end is that the
 * configuration arrived wired up: the column order, the computed columns, the
 * totals in the footer and the filtered views.
 *
 * `tableTemplates.test.ts` checks every spec in the catalogue is internally
 * consistent; these three walk the ones that use every capability at once.
 */

/** The grid row containing `text`. */
const row = (page: Page, text: string) =>
  page.getByRole('row').filter({ hasText: text });

/** Creates a table from a template card and waits for its grid. */
async function createFromTemplate(page: Page, template: RegExp, name: string) {
  await createTableFromDialog(page, { template, name });
  await waitForGridInteractive(page);
}

/** The column headings, left to right, as the view renders them. */
const headings = (page: Page) =>
  page.evaluate(() =>
    Array.from(document.querySelectorAll('[role="columnheader"]'))
      .slice(1)
      .map(el => (el.textContent ?? '').replace('Drag column', '').trim()),
  );

/** Types a value into one grid cell, addressed by its row and column index. */
async function setCell(
  page: Page,
  rowIndex: number,
  columnIndex: number,
  value: string,
  _opts: { replace?: boolean } = {},
) {
  // Matched loosely when the column reformats what it was given ("4.50"
  // renders as "4.5"); what is being ruled out is the cell being empty.
  await setGridCell(page, rowIndex, columnIndex, value, { match: /\S/ });
}

/**
 * Reloads and waits for the grid.
 *
 * Needed because a computed cell does not refresh in place — it keeps whatever it
 * computed at mount until the row is rendered afresh. See the React-Compiler gap
 * in `planning/table-templates-and-mini-apps.md`.
 */
test.describe('table templates', () => {
  test.beforeEach(before);

  test('the Create button carries the wait', async ({ page }) => {
    // A template is ~20 commits. The dialog used to close on submit and build
    // afterwards, which left the user on the previous page with no sign that
    // anything was happening.
    await newResource('table', page);
    await page.getByRole('button', { name: /Project tasks/ }).click();
    await page.getByPlaceholder('New Table').fill('Busy check');
    await page.getByRole('button', { name: 'Create' }).click();

    const busy = page.getByRole('button', { name: 'Creating table…' });
    await expect(busy).toBeVisible();
    await expect(busy).toHaveAttribute('aria-busy', 'true');
    await expect(busy).toBeDisabled();

    await expect(
      page.getByRole('heading', { name: 'Busy check' }).first(),
    ).toBeVisible({ timeout: 60_000 });
    await expect(busy).toHaveCount(0);
  });

  test('Expenses arrives with its order, its decimals and its totals', async ({
    page,
  }) => {
    test.slow();
    // The totals row is read cell by cell; a clipped cell can't be.
    await page.setViewportSize({ width: 1800, height: 900 });

    await createFromTemplate(page, /Expenses/, 'Spending');

    // The template's own column order, with the column it doesn't place (Notes)
    // following the ones it does.
    expect(await headings(page)).toEqual([
      'name',
      'Date',
      'Category',
      'Amount',
      'Receipt',
      'Notes',
    ]);

    // Amount is a decimal column, so an amount keeps its cents. This is the
    // whole reason `decimal` exists: an integer column would swallow them.
    await setCell(page, 2, 2, 'Coffee');
    await setCell(page, 2, 5, '4.50');
    await expect(row(page, 'Coffee')).toBeVisible();
    // The total is computed over the table's COLLECTION, which a still-virtual
    // row is not part of — so it would render an em-dash rather than a wrong
    // number, and the assertion below would be about an empty table.
    await waitForRowsMaterialized(page);

    // The sum under Amount was configured by the template — nobody opened a
    // menu to ask for it.
    //
    // When this fails on CI it reads "1ΣΣΣSum—ΣΣ": the label is there and the
    // value is an em-dash. Traced 2026-08-14 — the two `setCell` calls above
    // are two separate commits, and the aggregate read that follows the FIRST
    // correctly reports the row as a member with no value to sum. Only a read
    // that observes the second commit settles the total, so an em-dash here
    // means the last read predates the value, not that the total is wrong.
    // Don't widen the budget to cover it; the read is queued behind the
    // post-save write storm (see `useTableAggregates`' max-wait note).
    const footer = page.getByTestId('table-totals');
    await expect(footer).toContainText('Sum', { timeout: 15_000 });
    await expect(footer).toContainText('4.5', { timeout: 15_000 });

    // And it follows the data, as any total must.
    await setCell(page, 2, 5, '2.25', { replace: true });
    await expect(footer).toContainText('2.25', { timeout: 15_000 });

    // The second view stacks two statistics on the same column, in two footer
    // rows — also configuration, not something clicked together here.
    await page.getByRole('tab', { name: 'By category' }).click();
    await expect(page.getByTestId('table-totals')).toContainText('Sum', {
      timeout: 15_000,
    });
    await expect(page.getByTestId('table-totals-1')).toContainText('Average', {
      timeout: 15_000,
    });
  });

  test('Plant care works out when a plant is due', async ({ page }) => {
    test.slow();
    await page.setViewportSize({ width: 1800, height: 900 });

    await createFromTemplate(page, /Plant care/, 'Plants');

    // The template's own column order, then the button it puts on each row.
    expect(await headings(page)).toEqual([
      'name',
      'Species',
      'Last watered',
      'Thirsty for',
      'Water every',
      'Next water',
      'Location',
      'Notes',
      'Watered',
    ]);

    await setCell(page, 2, 2, 'Monstera');
    // dd-mm-yyyy: the suite runs in en-GB.
    await setCell(page, 2, 4, '15012026');
    await setCell(page, 2, 6, '7');
    await reloadGrid(page);

    const plant = row(page, 'Monstera');
    await expect(plant).toBeVisible();

    // Watered on the 15th, every 7 days: the next watering is the 22nd. Both of
    // the template's computed columns read the columns it wired them to — the
    // date from "Last watered", the interval from "Water every".
    const due = await page.evaluate(() =>
      new Date(Date.parse('2026-01-15') + 7 * 86_400_000).toLocaleDateString(),
    );
    await expect(plant.getByTestId('derived-next-water')).toHaveText(due, {
      timeout: 15_000,
    });
    await expect(plant.getByTestId('derived-thirsty-for')).toHaveText(
      /today|\d+d ago|in \d+d/,
    );
  });

  test('Inventory prices its stock and hides what is not running low', async ({
    page,
  }) => {
    test.slow();
    await page.setViewportSize({ width: 1800, height: 900 });

    await createFromTemplate(page, /Inventory/, 'Stockroom');

    // The template's own column order, then the buttons it puts on each row.
    expect(await headings(page)).toEqual([
      'name',
      'SKU',
      'Quantity',
      'Unit price',
      'Value',
      'Category',
      'Location',
      '+1',
      '-1',
    ]);

    await setCell(page, 2, 2, 'Bolts');
    await setCell(page, 2, 4, '2');
    await setCell(page, 2, 5, '0.30');
    // The Stock view has no sort, so the second row is the one below.
    await setCell(page, 3, 2, 'Crates');
    await setCell(page, 3, 4, '20');
    await reloadGrid(page);

    // Quantity × Unit price, computed per row.
    await expect(row(page, 'Bolts').getByTestId('derived-value')).toHaveText(
      '0.60',
      { timeout: 15_000 },
    );
    // 2 + 20 pieces in stock, totalled by the template. 30s on both: the
    // total needs an aggregate read to get through the ClientDb worker, and
    // post-reload that queue sits behind the re-drain's write storm for 15s+
    // on a loaded runner (measured ~18.5s in the instrumented CI runs).
    // Tracked as the OPFS write-amplification issue — when write count
    // drops, these budgets can too.
    await expect(page.getByTestId('table-totals')).toContainText('Sum', {
      timeout: 30_000,
    });
    await expect(page.getByTestId('table-totals')).toContainText('22', {
      timeout: 30_000,
    });

    // The second view is the same table with a filter on it: two bolts are low
    // stock, twenty crates are not.
    await page.getByRole('tab', { name: 'Low stock' }).click();
    await expect(
      page.getByRole('button', { name: /Quantity at most 3/ }),
    ).toBeVisible();
    await expect(row(page, 'Bolts')).toBeVisible({ timeout: 15_000 });
    await expect(row(page, 'Crates')).toHaveCount(0);

    // Restocking a low-stock item has to take it out of this view. The local
    // database answers a filtered view from its cached member list, so an edit
    // that ends a row's membership must delete that row's entry — otherwise the
    // row stays listed here for as long as the cache does, a reload included.
    await page.getByRole('tab', { name: 'Stock', exact: true }).click();
    await expect(page.getByRole('grid')).toBeVisible();
    await setCell(page, 2, 4, '40', { replace: true });
    await reloadGrid(page);

    await page.getByRole('tab', { name: 'Low stock' }).click();
    await expect(
      page.getByRole('button', { name: /Quantity at most 3/ }),
    ).toBeVisible();
    await expect(row(page, 'Bolts')).toHaveCount(0, { timeout: 15_000 });
    await expect(row(page, 'Crates')).toHaveCount(0);
  });
});
