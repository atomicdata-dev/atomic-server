import { before } from './session-fixtures';
import { test, expect, type Page } from './session-fixtures';
import {
  createTableFromDialog,
  inDialog,
  reloadGrid,
  waitForGridMounted,
} from './test-utils';

async function addDateTimeColumn(page: Page, name: string) {
  await page.getByRole('button', { name: 'Add column' }).click();
  await page.click('text=Date');
  await inDialog(page, async (dialog, closeDialogWith) => {
    await dialog.getByPlaceholder('New Column').fill(name);
    await dialog.getByLabel('Include Time').click();
    await closeDialogWith('Create');
  });
  await expect(page.getByRole('button', { name })).toBeVisible({
    timeout: 15_000,
  });
}

async function addDurationColumn(page: Page) {
  await page.getByRole('button', { name: 'Add column' }).click();
  await page.getByTestId('menu-item-computed').click();

  await inDialog(page, async () => {
    await page.getByTestId('derived-kind').selectOption('difference');
    await page.getByTestId('derived-label').fill('Duration');
    await page
      .getByTestId('derived-arg-from')
      .selectOption({ label: 'Starts' });
    await page.getByTestId('derived-arg-to').selectOption({ label: 'Ends' });
    await page.getByTestId('derived-save').click();
  });
}

test.describe('inline row persistence', () => {
  test.beforeEach(before);

  // #1987: Tab out of the last stored column of a new row lands on a computed
  // column. The draft row had no cell there, so focus fell to <body>, the grid
  // never saw the Escape, and the row stayed an unsaved draft: visible, absent
  // from the footer count and the computed cells, and gone after a reload.
  test('a row typed inline up to a computed column is saved on Escape', async ({
    page,
  }) => {
    await createTableFromDialog(page, { name: 'Rehearsals' });
    await page.keyboard.press('Escape');
    await expect(page.getByRole('gridcell').first()).toBeVisible();
    await addDateTimeColumn(page, 'Starts');
    await addDateTimeColumn(page, 'Ends');
    await addDurationColumn(page);
    await waitForGridMounted(page);

    const input = page.locator('[role="grid"] input').first();

    await page.locator('[aria-rowindex="2"] > [aria-colindex="2"]').click();
    await page.keyboard.press('Enter');
    await input.fill('Overnight rehearsal');
    await page.keyboard.press('Tab');
    await input.fill('2026-10-26T20:00');
    await page.keyboard.press('Tab');
    await input.fill('2026-10-26T21:00');
    await page.keyboard.press('Tab');

    // The cursor is on the computed cell, and that cell owns the keyboard.
    await expect(
      page.locator('[aria-rowindex="2"] > [aria-colindex="5"]'),
    ).toBeFocused();
    await page.keyboard.press('Escape');

    // The row is saved, so the computed cell can read it.
    await expect(
      page.locator('[aria-rowindex="2"]').getByText('1:00:00'),
    ).toBeVisible();

    await reloadGrid(page);

    const saved = page.getByRole('row').filter({ hasText: 'Overnight' });
    await expect(saved).toBeVisible();
    await expect(saved.getByText('1:00:00')).toBeVisible();
  });
});
