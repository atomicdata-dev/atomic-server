import { test, expect } from './fixtures';
import { before, newResource, setTitle, typeInSearch } from './test-utils';

test.describe('command palette actions', () => {
  test.beforeEach(before);

  test('cmd+k shows matching registry actions and runs one', async ({
    page,
  }) => {
    await newResource('folder', page);
    await setTitle(page, 'PaletteFolder');
    await page.keyboard.press('Escape');

    await typeInSearch(page, 'history');
    const historyAction = page.getByTestId('palette-action-history');
    await expect(historyAction).toBeVisible();
    await expect(page.getByText('Actions', { exact: true })).toBeVisible();

    await historyAction.click();
    await expect(page).toHaveURL(/history/);
  });

  test('cmd+k does not interleave actions into a resource-name query', async ({
    page,
  }) => {
    await typeInSearch(page, 'avocado');
    await expect(page.getByTestId('palette-action-history')).toHaveCount(0);
    await expect(page.getByTestId('palette-action-delete')).toHaveCount(0);
    await expect(page.getByTestId('palette-action-edit')).toHaveCount(0);
  });
});
