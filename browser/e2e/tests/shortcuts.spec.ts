import { test, expect, type Page } from './fixtures';
import { before } from './test-utils';

test.describe('keyboard shortcuts', () => {
  test.beforeEach(before);

  test('? opens the shortcuts overlay; backslash toggles the sidebar', async ({
    page,
  }: {
    page: Page;
  }) => {
    // Shift+/ ("?") opens the shortcuts overlay. The list is rendered from
    // the central shortcuts registry — "Go to parent" only exists there.
    await page.keyboard.press('Shift+Slash');
    await expect(page.getByText('Show keyboard shortcuts')).toBeVisible();
    await expect(page.getByText('Go to parent')).toBeVisible();

    // The overlay's input filters the list.
    await page.getByPlaceholder(/Filter shortcuts/).fill('parent');
    await expect(page.getByText('Go to parent')).toBeVisible();
    await expect(page.getByText('Show keyboard shortcuts')).toHaveCount(0);

    await page.keyboard.press('Escape');
    await expect(page.getByText('Go to parent')).toHaveCount(0);

    // Backslash toggles the sidebar lock. The sidebar slides out via a
    // transform (still "visible" to Playwright), so assert on the persisted
    // setting the hotkey flips.
    // (unset until first toggle; defaults to true on a wide viewport)
    const sideBarLocked = () =>
      page.evaluate(() => localStorage.getItem('sideBarOpen'));
    await page.keyboard.press('Backslash');
    await expect.poll(sideBarLocked).toBe('false');
    await page.keyboard.press('Backslash');
    await expect.poll(sideBarLocked).toBe('true');
  });
});
