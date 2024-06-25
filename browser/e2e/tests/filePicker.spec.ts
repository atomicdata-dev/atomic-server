import { test, expect, Page } from '@playwright/test';

import {
  FRONTEND_URL,
  REBUILD_INDEX_TIME,
  before,
  currentDialog,
  fillSearchBox,
  newDrive,
  newResource,
  sideBarNewResourceTestId,
  signIn,
  testFilePath,
  waitForCommit,
} from './test-utils';

const ONTOLOGY_NAME = 'filepicker-test';

const uploadFile = async (page: Page, fileName: string) => {
  await page.getByTestId(sideBarNewResourceTestId).click();
  await expect(page).toHaveURL(`${FRONTEND_URL}/app/new`);

  const fileChooserPromise = page.waitForEvent('filechooser');

  await page
    .getByRole('button', { name: 'Drop files or click here to upload.' })
    .click();

  const fileChooser = await fileChooserPromise;

  fileChooser.setFiles(testFilePath(fileName));

  await expect(page.getByText(fileName)).toHaveCount(2);
};

// Creates an ontology with a class we can use to test the file picker.
const createModel = async (page: Page) => {
  await newResource('ontology', page);

  await page.getByPlaceholder('my-ontology').fill(ONTOLOGY_NAME);
  await currentDialog(page).getByRole('button', { name: 'Create' }).click();

  await expect(page.locator(`h1:has-text("${ONTOLOGY_NAME}")`)).toBeVisible();

  await page.getByRole('button', { name: 'Add class', exact: true }).click();
  await page.getByPlaceholder('shortname').fill('robot');
  await page.getByRole('button', { name: 'Save' }).click();

  await expect(page.locator('input[value="robot"]')).toBeVisible();

  await page.getByRole('button', { name: 'add required property' }).click();
  await page
    .getByPlaceholder('Search for a property or enter a URL')
    .fill('programming');

  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Enter');

  await page.getByRole('button', { name: 'Configure programming' }).click();

  await currentDialog(page)
    .getByLabel('Datatype')
    .selectOption('https://atomicdata.dev/datatypes/atomicURL');

  await expect(currentDialog(page).getByLabel('Classtype')).not.toBeDisabled();

  await fillSearchBox(
    currentDialog(page),
    'Search for a class',
    'https://atomicdata.dev/classes/File',
    { label: 'Classtype' },
  );

  const commitPromise = waitForCommit(page);
  await page.keyboard.press('Enter');
  await commitPromise;
  await expect(currentDialog(page).getByLabel('Classtype')).toHaveText('file');

  await currentDialog(page).getByRole('button', { name: 'close' }).click();
};

test.describe('File Picker', () => {
  test.beforeEach(before);

  test('select file and upload using the filepicker', async ({ page }) => {
    await signIn(page);
    await newDrive(page);

    await uploadFile(page, 'testFile1.txt');
    await uploadFile(page, 'testFile2.md');

    await createModel(page);

    // The new resource page relies on the search API to show ontology class buttons. If the prossess of creating the ontology took less than 5 seconds it will not appear on the new resource page.
    await page.waitForTimeout(REBUILD_INDEX_TIME);

    {
      // Test selecting an existing file.
      await newResource('robot', page);

      await expect(
        page.getByRole('heading', { name: 'new robot' }),
      ).toBeVisible();

      await expect(
        page.getByRole('button', { name: 'Select File' }),
      ).toBeVisible();

      await page.getByRole('button', { name: 'Select File' }).click();

      const filepicker = currentDialog(page);
      await expect(filepicker.getByPlaceholder('Search...')).toBeVisible();
      await expect(
        filepicker.getByText('Contents of test file 1'),
      ).toBeVisible();
      await expect(filepicker.getByText('testFile2.md')).toBeVisible();

      await filepicker.getByPlaceholder('Search...').fill('.md');

      await expect(
        filepicker.getByText('Contents of test file 1'),
      ).not.toBeVisible();

      await filepicker.getByRole('button', { name: 'testFile2.md' }).click();

      await expect(filepicker).not.toBeVisible();
      await expect(
        page.getByText('first step in understanding recursion?'),
      ).toBeVisible();

      await page.getByRole('button', { name: 'Save' }).click();
      await expect(page.getByText('New robot')).not.toBeVisible();
    }

    {
      // Test uploading a new file.
      await newResource('robot', page);

      await expect(
        page.getByRole('heading', { name: 'new robot' }),
      ).toBeVisible();

      await page.getByRole('button', { name: 'Select File' }).click();

      const filepicker = currentDialog(page);
      await expect(filepicker.getByPlaceholder('Search...')).toBeVisible();

      await filepicker
        .getByLabel('Upload')
        .setInputFiles(testFilePath('testFile3.txt'));

      await expect(filepicker).not.toBeVisible();
      await expect(
        page.getByText('File preview not available at this time'),
      ).toBeVisible();

      await page.getByRole('button', { name: 'Save' }).click();
      await expect(page.getByText('New robot')).not.toBeVisible();
      await expect(page.getByText('testFile3.txt').nth(1)).toBeVisible();
      await page.getByText('testFile3.txt').nth(1).click();

      // For some reason playwright will only find text with quotes in them when using a regex instead of string.
      await expect(page.getByText(/It's a secret to everybody/)).toBeVisible();
    }
  });
});
