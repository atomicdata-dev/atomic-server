import { test, expect, type Page } from './fixtures';
import {
  before,
  createTableFromDialog,
  inDialog,
  pickTotal,
  setGridCell,
  waitForGridMounted,
} from './test-utils';

/** The grid row containing `text`. */
const row = (page: Page, text: string) =>
  page.getByRole('row').filter({ hasText: text });

/**
 * Puts `value` in one grid cell, addressed by its row and column index.
 *
 * Uses the editor `<input>`'s `fill`, not keystrokes: under CI load
 * Control+A misses, typing appends, and the Hours cell became `"34"` —
 * after which `toContainText('6')` on the footer false-passed on a sum of 36.
 */
async function setCell(
  page: Page,
  rowIndex: number,
  columnIndex: number,
  value: string,
) {
  await setGridCell(page, rowIndex, columnIndex, value);
}

// Totals assertions use 30s budgets, not the 10s default: an aggregate value
// needs its read to get through the ClientDb worker, and after saves/reloads
// that queue sits behind a write storm for 15s+ on a loaded runner (measured
// ~18.5s in the instrumented CI runs; same budget as row-actions and
// table-templates). Tracked as the OPFS write-amplification issue — when
// write count drops, these budgets can too.
test.describe('table totals', () => {
  test.beforeEach(before);

  test('sums and counts every matching row, and breaks them down', async ({
    page,
  }) => {
    test.slow();

    // Wide enough that the whole table fits: the totals row is clicked cell by
    // cell, and a cell clipped by the window edge can't be.
    await page.setViewportSize({ width: 1800, height: 900 });

    // The Time tracker template gives a timestamp column and a fast way to make
    // rows: start an entry and stop it.
    await createTableFromDialog(page, {
      template: /Time tracker/,
      name: 'Totals',
    });

    await expect(page.getByTestId('timer-new-input')).toBeVisible();
    await waitForGridMounted(page);

    for (const name of ['Alpha', 'Beta']) {
      await page.getByTestId('timer-new-input').fill(name);
      await page.getByTestId('timer-start-new').click();
      await expect(row(page, name)).toBeVisible();
      await row(page, name).getByTestId('timer-stop').click();
      await expect(row(page, name).getByTestId('timer-resume')).toBeVisible();
    }

    // Do the rest in the plain table view: totals are not a timer feature.
    await page.getByRole('tab', { name: 'All entries' }).click();
    await expect(page.getByTestId('timer-new-input')).toHaveCount(0);
    await expect(page.getByRole('grid')).toBeVisible();

    // A number column to add up.
    await page.getByRole('button', { name: 'Add column' }).click();
    await page.click('text=Number');
    await inDialog(page, async (dialog, closeDialogWith) => {
      await dialog.getByPlaceholder('New Column').fill('Hours');
      await closeDialogWith('Create');
    });
    await expect(
      page.getByRole('button', { name: 'Hours', exact: true }),
    ).toBeVisible();

    // Address the column by its heading rather than by a hardcoded position: the
    // template's own columns (and its computed Duration) sit to the left of it,
    // and a template gaining a column must not break this test.
    const hoursColumn = await page
      .locator('[role="columnheader"]')
      .filter({ hasText: 'Hours' })
      .first()
      .getAttribute('aria-colindex');
    const hours = Number(hoursColumn);
    expect(hours).toBeGreaterThan(1);

    // Data rows start at aria-rowindex 2 (1 is the header).
    await setCell(page, 2, hours, '2');
    await setCell(page, 3, hours, '3');

    // Total the Hours column from its own footer cell — the totals live under
    // the columns they describe.
    const footer = page.getByTestId('table-totals');
    await pickTotal(page, footer.locator(`[aria-colindex="${hours}"]`), 'sum');

    // The store computed it over every matching row.
    await expect(footer).toContainText('5', { timeout: 30_000 });

    // It follows an edit, without a reload: 2 + 4 = 6.
    await setCell(page, 3, hours, '4');
    await expect(footer.locator(`[aria-colindex="${hours}"]`)).toContainText(
      '6',
      { timeout: 30_000 },
    );

    // The menu must come back on the same cell, again and again: a cell whose
    // menu opens once and then goes dead is the failure this covers.
    await pickTotal(page, footer.locator(`[aria-colindex="${hours}"]`), 'avg');
    await expect(footer).toContainText('Average', { timeout: 30_000 });

    // ...including after visiting another column's cell in between.
    // Opening a menu is not idempotent — the cell TOGGLES its menu, so a click
    // landing while the previous one is still closing closes this one instead.
    // `pickFromMenu` cannot help here: this only checks what the menu offers,
    // it does not choose anything.
    await expect(async () => {
      await footer.locator('[aria-colindex="2"]').click();
      await expect(
        page.getByTestId('menu-item-count').filter({ visible: true }).first(),
      ).toBeVisible({ timeout: 2_000 });
    }).toPass({ timeout: 30_000 });
    await page.keyboard.press('Escape');
    await pickTotal(page, footer.locator(`[aria-colindex="${hours}"]`), 'sum');
    await expect(footer).toContainText('Sum', { timeout: 30_000 });

    // A second totals row: the same column can show a sum and an average.
    await pickTotal(page, footer.locator('[aria-colindex="1"]'), 'add-row');
    const secondRow = page.getByTestId('table-totals-1');
    await expect(secondRow).toBeVisible();
    await pickTotal(
      page,
      secondRow.locator(`[aria-colindex="${hours}"]`),
      'avg',
    );

    // 2 and 4 → sum 6, average 3, each in its own row under Hours.
    await expect(footer.locator(`[aria-colindex="${hours}"]`)).toContainText(
      '6',
      { timeout: 30_000 },
    );
    await expect(secondRow.locator(`[aria-colindex="${hours}"]`)).toContainText(
      '3',
      { timeout: 30_000 },
    );

    // Break the totals down per day, from the row-count cell's menu. (Its menu
    // was used a moment ago, so let that one finish closing first.)
    await expect(page.locator('[role="menu"]')).toHaveCount(0);
    await pickTotal(page, footer.locator('[aria-colindex="1"]'), 'breakdown');
    await inDialog(page, async () => {
      await page
        .getByTestId('breakdown-column')
        .selectOption({ label: 'Start' });
      await page.getByTestId('breakdown-save').click();
    });

    // Both entries started today, so one bucket of 2 rows.
    const breakdown = page.getByTestId('table-breakdown');
    await expect(breakdown).toBeVisible({ timeout: 30_000 });
    await expect(breakdown).toContainText('2 rows');

    // A filter narrows the rows AND the total with them — the totals describe
    // what you are looking at, not the whole table.
    await page.getByTitle('Filter', { exact: true }).click();
    await page.getByRole('menuitem', { name: 'Hours', exact: true }).click();
    await page.getByPlaceholder('Value…').fill('4');
    await page.keyboard.press('Escape');

    await expect(row(page, 'Alpha')).toHaveCount(0);
    // Only Beta's 4 hours are left, so the total says 4 over 1 row.
    await expect(footer).toContainText('4', { timeout: 30_000 });
    await expect(footer.locator('[aria-colindex="1"]')).toHaveText('1');

    // The configuration lives on the View, so it survives a reload.
    await page.reload();
    await expect(page.getByRole('grid')).toBeVisible();
    await expect(page.getByTestId('table-totals')).toContainText('Sum', {
      timeout: 30_000,
    });
    // Both totals rows are configuration on the View, so both come back.
    await expect(page.getByTestId('table-totals-1')).toContainText('Average', {
      timeout: 30_000,
    });
  });
});
