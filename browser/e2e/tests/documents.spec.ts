import { test, expect } from '@playwright/test';
import {
  signIn,
  newDrive,
  newResource,
  editTitle,
  editableTitle,
  getCurrentSubject,
  makeDrivePublic,
  openNewSubjectWindow,
  timestamp,
  before,
  waitForCommitOnCurrentResource,
} from './test-utils';
test.describe('documents', async () => {
  test.beforeEach(before);

  test('create document, edit, page title, websockets', async ({
    page,
    browser,
  }) => {
    await signIn(page);
    await newDrive(page);
    await makeDrivePublic(page);
    // Create a document
    await newResource('document', page);
    const title = `Document ${timestamp()}`;
    await editTitle(title, page);

    await page.press(editableTitle, 'Enter');

    const teststring = `My test: ${timestamp()}`;

    const waiter = waitForCommitOnCurrentResource(page);
    await page.fill('textarea', teststring);
    await waiter;

    await expect(page.locator(`text=${teststring}`)).toBeVisible();

    // multi-user
    const currentSubject = await getCurrentSubject(page);
    const page2 = await openNewSubjectWindow(browser, currentSubject!);
    await expect(
      page2.locator(`text=${teststring}`),
      'First paragraph title not visible in second tab. Not a websocket issue',
    ).toBeVisible();
    expect(await page2.title()).toEqual(title);

    // Add a new line on first page, check if it appears on the second
    await page.keyboard.press('Enter');
    const syncText = 'New paragraph';
    await page.keyboard.type(syncText);
    await expect(
      page2.locator(`text=${syncText}`),
      'New paragraph not found in second window. Websockets may not be working.',
    ).toBeVisible();

    // Delete a row, cmd + backspace
    await page.keyboard.down('Meta');
    await page.keyboard.press('Backspace');
    await expect(
      page.locator(`text=${syncText}`),
      'Paragraph not deleted in first window.',
    ).not.toBeVisible();
    await expect(
      page2.locator(`text=${syncText}`),
      'Paragraph not deleted in second window',
    ).not.toBeVisible();
  });
});
