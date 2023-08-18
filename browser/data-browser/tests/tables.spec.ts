import { test, expect } from '@playwright/test';
import {
  signIn,
  newDrive,
  newResource,
  waitForCommit,
  before,
} from './test-utils';
test.describe('tables', async () => {
  test.beforeEach(before);

  test('create and fill', async ({ page }) => {
    const newColumn = async (type: string) => {
      await page.getByRole('button', { name: 'Add column' }).click();
      await page.click(`text=${type}`);
    };

    const tab = async () => {
      await page.keyboard.press('Tab');
    };

    const createTag = async (emote: string, name: string) => {
      await page.getByPlaceholder('New tag').last().fill(name);
      await page.getByTitle('Pick an emoji').last().click();
      await page.getByPlaceholder('Search', { exact: true }).fill(emote);
      await page.getByRole('button', { name: emote }).click();
      await page.getByTitle('Add tag').last().click();
      await expect(page.getByRole('button', { name })).toBeVisible();
    };

    const pickTag = async (name: string) => {
      await page.keyboard.type(name);
      await page.keyboard.press('Enter');
      await page.keyboard.press('Escape');
      await expect(page.getByPlaceholder('filter tags')).not.toBeVisible();
    };

    const fillRow = async (currentRowNumber: number, row) => {
      const { name, date, number, checkbox, select } = row;
      const rowIndex = currentRowNumber + 1;
      await page.keyboard.type(name);
      // Flay newline
      await page.waitForTimeout(300);
      await tab();
      // Wait for the table to refresh by checking if the next row is visible
      await expect(
        page.getByRole('rowheader', { name: `${rowIndex}` }),
      ).toBeAttached();

      await page.keyboard.type(date);
      await tab();
      await page.keyboard.type(number);
      await tab();

      if (checkbox) {
        await page.keyboard.press('Space');

        // Check if checked
        await expect(
          page.locator(`[aria-rowindex="${rowIndex}"]`).getByRole('checkbox'),
          "Checkbox isn't checked",
        ).toBeChecked();
      }

      await tab();
      await pickTag(select);
      await tab();
      await expect(
        page.getByRole('gridcell', { name: row.name }),
        `${row.name} row not visible`,
      ).toBeVisible();
    };

    // --- Test Start ---
    await signIn(page);
    await newDrive(page);

    // Create new Table
    await newResource('table', page);

    // Name table
    const tableName = 'Made up music genres';
    await page.getByPlaceholder('New Table').fill(tableName);
    await page.locator('button:has-text("Create")').click();
    await expect(page.locator(`h1:has-text("${tableName}")`)).toBeVisible();

    // Create Date column
    await newColumn('Date');
    await expect(page.locator('text=New Date Column')).toBeVisible();
    const dateColumnName = 'Existed since';
    await page
      .locator('[placeholder="New Column"] >> visible = true')
      .fill(dateColumnName);
    await page.getByLabel('Long').click();
    await page.locator('button:has-text("Create")').click();
    await waitForCommit(page);
    await expect(page.locator('text=New Date Column')).not.toBeVisible();
    await expect(
      page.getByRole('button', { name: dateColumnName }),
    ).toBeVisible();

    // Create Number column
    await newColumn('Number');
    const numberColumnName = 'Number of tracks';
    await expect(page.locator('text=New Number Column')).toBeVisible();
    await page
      .locator('[placeholder="New Column"] >> visible = true')
      .fill(numberColumnName);

    await page.locator('button:has-text("Create")').click();
    await waitForCommit(page);
    await expect(page.locator('text=New Number Column')).not.toBeVisible();
    await expect(
      page.getByRole('button', { name: numberColumnName }),
    ).toBeVisible();

    // Create Checkbox column
    await newColumn('Checkbox');
    await expect(page.locator('text=New Checkbox Column')).toBeVisible();
    const checkboxColumnName = 'Approved by W3C';
    await page
      .locator('[placeholder="New Column"] >> visible = true')
      .fill(checkboxColumnName);
    await page.locator('button:has-text("Create")').click();
    await waitForCommit(page);
    await expect(page.locator('text=New Checkbox Column')).not.toBeVisible();
    await expect(
      page.getByRole('button', { name: checkboxColumnName }),
    ).toBeVisible();

    // Create Select column
    await newColumn('Select');
    const selectColumnName = 'Descriptive words';
    await expect(page.locator('text=New Select Column')).toBeVisible();
    await page
      .locator('[placeholder="New Column"] >> visible = true')
      .fill(selectColumnName);

    await createTag('😤', 'wild');
    await createTag('😵‍💫', 'dreamy');
    await createTag('🤨', 'wtf');
    await page.locator('button:has-text("Create")').click();
    await waitForCommit(page);
    await expect(page.locator('text=New Select Column')).not.toBeVisible();
    await expect(
      page.getByRole('button', { name: selectColumnName }),
    ).toBeVisible();

    // Check if table has loaded.
    await expect(
      page.getByRole('button', { name: selectColumnName }),
    ).toBeVisible();

    await page.waitForLoadState('networkidle');
    await page.reload();
    await expect(
      page.getByRole('button', { name: selectColumnName }),
    ).toBeVisible();

    const rows = [
      {
        name: 'Progressive Pizza House',
        date: '04032000',
        number: '10',
        checkbox: true,
        select: 'dreamy',
      },
      {
        name: 'Drum or Bass',
        date: '15051980',
        number: '3000035',
        checkbox: false,
        select: 'wild',
      },
      {
        name: 'Mumble Punk',
        date: '13051965',
        number: '60',
        checkbox: true,
        select: 'wtf',
      },
    ];
    // Start filling cells
    await page.getByRole('gridcell').first().click({ force: true });
    await expect(page.getByRole('gridcell').first()).toBeFocused();
    await page.waitForTimeout(100);

    for (const row of rows) {
      await fillRow(1, row);
    }

    // Disabled date tests until Playwright bug fixed
    // await expect(
    //   page.getByRole('gridcell', { name: '4 March 2000' }),
    // ).toBeVisible();
    // await expect(
    //   page.getByRole('gridcell', { name: '15 May 1980' }),
    // ).toBeVisible();
    // await expect(
    //   page.getByRole('gridcell', { name: '13 May 1965' }),
    // ).toBeVisible();
    await expect(
      page.getByRole('gridcell', { name: '😵‍💫 dreamy' }),
    ).toBeVisible();
    await expect(page.getByRole('gridcell', { name: '😤 wild' })).toBeVisible();
    await expect(page.getByRole('gridcell', { name: '🤨 wtf' })).toBeVisible();

    // Move to the first cell and change its content.
    await page.keyboard.press('Escape');
    await page.keyboard.press('ArrowUp');
    await page.keyboard.press('ArrowUp');
    await page.keyboard.press('ArrowUp');
    const newName = 'Progressive Peperoni Pizza House';
    await page.keyboard.type(newName);
    await page.keyboard.press('Escape');

    await expect(
      page.getByRole('gridcell', { name: rows[0].name }),
      "Old cell name shouldn't be visible",
    ).not.toBeVisible();

    await expect(
      page.getByRole('gridcell', { name: newName }),
      'New cell name not visible',
    ).toBeVisible();

    // Move to the index cell on the second row and delete the row.
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('ArrowLeft');
    await page.keyboard.press('Backspace');

    await expect(
      page.getByRole('gridcell', { name: 'Drum or Bass' }),
    ).not.toBeVisible();
  });
});
