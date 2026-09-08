import { test, expect } from './fixtures';
import { before, FRONTEND_URL } from './test-utils';

test.describe('settings', () => {
  test.beforeEach(before);

  test('finds the page transition animation toggle with settings search', async ({
    page,
  }) => {
    await page.goto(`${FRONTEND_URL}/app/settings`);

    const settingsSearch = page.getByPlaceholder('Search settings...');
    const transitionToggle = page.getByRole('checkbox', {
      name: 'Disable page transition animations',
    });

    await settingsSearch.fill('transition');
    await expect(transitionToggle).toBeVisible();

    await settingsSearch.fill('animation');
    await expect(transitionToggle).toBeVisible();
  });
});
