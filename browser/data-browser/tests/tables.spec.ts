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

    const fillRow = async (
      currentRowNumber: number,
      col1: string,
      col2: string,
      col3: string,
      col4: boolean,
      col5: string,
    ) => {
      const rowIndex = currentRowNumber + 1;
      await page.keyboard.type(col1);
      await tab();
      // Wait for the table to refresh by checking if the next row is visible
      await expect(
        page.getByRole('rowheader', { name: `${rowIndex}` }),
      ).toBeAttached();

      await page.keyboard.type(col2);
      await tab();
      await page.keyboard.type(col3);
      await tab();

      if (col4) {
        await page.keyboard.press('Space');

        // Check if checked
        await expect(
          page.locator(`[aria-rowindex="${rowIndex}"]`).getByRole('checkbox'),
          "Checkbox isn't checked",
        ).toBeChecked();
      }

      await tab();
      await pickTag(col5);
      await tab();
    };

    // --- Test Start ---
    await signIn(page);
    await newDrive(page);

    // Create new Table
    await newResource('table', page);

    // Name table
    await page.getByPlaceholder('New Table').fill('Made up music genres');
    await page.locator('button:has-text("Create")').click();
    await expect(
      page.locator('h1:has-text("Made up music genres")'),
    ).toBeVisible();

    // Create Date column
    await newColumn('Date');
    await expect(page.locator('text=New Date Column')).toBeVisible();
    await page
      .locator('[placeholder="New Column"] >> visible = true')
      .fill('Existed since');
    await page.getByLabel('Long').click();
    await page.locator('button:has-text("Create")').click();
    await waitForCommit(page);
    await expect(page.locator('text=New Date Column')).not.toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Existed since' }),
    ).toBeVisible();

    // Create Number column
    await newColumn('Number');
    await expect(page.locator('text=New Number Column')).toBeVisible();
    await page
      .locator('[placeholder="New Column"] >> visible = true')
      .fill('Number of tracks');

    await page.locator('button:has-text("Create")').click();
    await waitForCommit(page);
    await expect(page.locator('text=New Number Column')).not.toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Number of tracks' }),
    ).toBeVisible();

    // Create Checkbox column
    await newColumn('Checkbox');
    await expect(page.locator('text=New Checkbox Column')).toBeVisible();
    await page
      .locator('[placeholder="New Column"] >> visible = true')
      .fill('Approved by W3C');

    await page.locator('button:has-text("Create")').click();
    await waitForCommit(page);
    await expect(page.locator('text=New Checkbox Column')).not.toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Approved by W3C' }),
    ).toBeVisible();

    // Create Select column
    await newColumn('Select');
    await expect(page.locator('text=New Select Column')).toBeVisible();
    await page
      .locator('[placeholder="New Column"] >> visible = true')
      .fill('Descriptive words');

    await createTag('😤', 'wild');
    await createTag('😵‍💫', 'dreamy');
    await createTag('🤨', 'wtf');
    await page.locator('button:has-text("Create")').click();
    await waitForCommit(page);
    await expect(page.locator('text=New Select Column')).not.toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Descriptive words' }),
    ).toBeVisible();

    // Check if table has loaded.
    await expect(
      page.getByRole('button', { name: 'Descriptive words' }),
    ).toBeVisible();

    await page.reload();
    await expect(
      page.getByRole('button', { name: 'Descriptive words' }),
    ).toBeVisible();

    // Start filling cells
    await page.getByRole('gridcell').first().click({ force: true });
    await expect(page.getByRole('gridcell').first()).toBeFocused();
    await page.waitForTimeout(100);
    const firstCellName = 'Progressive Pizza House';
    await fillRow(1, firstCellName, '04032000', '10', true, 'dreamy');
    await fillRow(2, 'Drum or Bass', '15051980', '3000035', false, 'wild');
    await fillRow(3, 'Mumble Punk', '13051965', '60', true, 'wtf');

    // Check if cells have been filled correctly
    await expect(
      page.getByRole('gridcell', { name: firstCellName }),
    ).toBeVisible();
    await expect(
      page.getByRole('gridcell', { name: 'Drum or Bass' }),
    ).toBeVisible();
    await expect(
      page.getByRole('gridcell', { name: 'Mumble Punk' }),
    ).toBeVisible();
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
      page.getByRole('gridcell', { name: firstCellName }),
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
