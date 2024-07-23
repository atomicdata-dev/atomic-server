import { test, expect } from '@playwright/test';
import {
  signIn,
  newDrive,
  waitForCommit,
  before,
  REBUILD_INDEX_TIME,
  addressBar,
  clickSidebarItem,
  editTitle,
  setTitle,
  sideBarNewResourceTestId,
  contextMenuClick,
} from './test-utils';
test.describe('search', async () => {
  test.beforeEach(before);

  test('text search', async ({ page }) => {
    await page.fill(addressBar, 'welcome');
    await expect(page.locator('text=Welcome to your')).toBeVisible();
    await page.keyboard.press('Enter');
    await expect(page.locator('text=resources:')).toBeVisible();
  });

  test('scoped search', async ({ page }) => {
    await signIn(page);
    await newDrive(page);

    // Create folder called 1
    await page.getByTestId(sideBarNewResourceTestId).click();
    await page.locator('button:has-text("folder")').click();
    await setTitle(page, 'Salad folder');

    // Create document called 'Avocado Salad'
    await page.locator('button:has-text("New Resource")').click();
    await page.locator('button:has-text("document")').click();
    await waitForCommit(page);
    // commit for initializing the first element (paragraph)
    await waitForCommit(page);
    await editTitle('Avocado Salad', page);

    await page.getByTestId(sideBarNewResourceTestId).click();

    // Create folder called 'Cake folder'
    await page.locator('button:has-text("folder")').click();
    await setTitle(page, 'Cake Folder');

    // Create document called 'Avocado Salad'
    await page.locator('button:has-text("New Resource")').click();
    await page.locator('button:has-text("document")').click();
    await waitForCommit(page);
    // commit for initializing the first element (paragraph)
    await waitForCommit(page);
    await editTitle('Avocado Cake', page);

    await clickSidebarItem('Cake Folder', page);

    // Set search scope to 'Cake folder'
    await page.waitForTimeout(REBUILD_INDEX_TIME);
    await page.reload();
    await contextMenuClick('scope', page);
    // Search for 'Avocado'
    await page.locator('[data-test="address-bar"]').type('Avocado');
    // I don't like the `.first` here, but for some reason there is one frame where
    // Multiple hits render, which fails the tests.
    await expect(page.locator('h2:text("Avocado Cake")').first()).toBeVisible();
    await expect(page.locator('h2:text("Avocado Salad")')).not.toBeVisible();

    // Remove scope
    await page.locator('button[title="Clear scope"]').click();

    await expect(page.locator('h2:text("Avocado Cake")').first()).toBeVisible();
    await expect(
      page.locator('h2:text("Avocado Salad")').first(),
    ).toBeVisible();
  });
});
