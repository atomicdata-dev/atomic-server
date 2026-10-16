import AxeBuilder from '@axe-core/playwright';
import { before } from './session-fixtures';
import { test, expect } from './session-fixtures';
import { createTableFromDialog, waitForGridInteractive } from './test-utils';

/**
 * The row dialog is where a table row is read and edited as a form (#1796).
 * Its labels are the property names a person gave the columns, clicking one
 * keeps them on the table, and every input is named by its label.
 *
 * The "Each child in a list should have a unique key" warning that editing a
 * value used to log is caught by the browser-diagnostics fixture: it only
 * shows with the i18n transform, which vitest does not run.
 */
test.describe('row dialog', () => {
  test.beforeEach(before);

  test('labels fields by name and names the checkbox', async ({ page }) => {
    await createTableFromDialog(page, {
      template: /Grocery list/,
      name: 'Groceries',
    });
    await expect(page.getByRole('grid')).toBeVisible();
    await waitForGridInteractive(page);

    const add = page.getByPlaceholder('What do you need?');
    await add.fill('Milk');
    await add.press('Enter');

    const rowHeader = page
      .locator('[role="rowheader"]')
      .filter({ hasText: /^1$/ });
    await rowHeader.hover();
    await rowHeader.getByTitle('Open resource').click();

    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('Milk').first()).toBeVisible();

    // Names, not shortnames.
    const bought = dialog.locator('label', { hasText: 'Bought' });
    await expect(bought).toBeVisible();
    await expect(
      dialog.locator('label', { hasText: 'Quantity' }),
    ).toBeVisible();

    // A label is not a way off the table.
    const url = page.url();
    await dialog.locator('label', { hasText: 'Aisle' }).click();
    expect(page.url()).toBe(url);
    await expect(dialog).toBeVisible();
    await expect(
      dialog.getByRole('link', { name: 'Open Bought in a new tab' }),
    ).toHaveAttribute('target', '_blank');

    // Editing the Bought value shows a checkbox named after its label.
    await bought
      .locator('xpath=ancestor::*[2]')
      .getByTitle('Click to add a value')
      .click();
    await expect(
      dialog.getByRole('checkbox', { name: 'Bought' }),
    ).toBeVisible();

    const { violations } = await new AxeBuilder({ page })
      .include('dialog[open]')
      .withRules(['label', 'link-name'])
      .analyze();
    expect(violations.map(v => `${v.id}: ${v.nodes.length}`)).toEqual([]);
  });
});
