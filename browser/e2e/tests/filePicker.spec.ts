import { test, expect, Page } from './fixtures';

import {
  DIALOG_CLOSE_BUTTON,
  FRONTEND_URL,
  SEARCHBOX_PROPERTY_PLACEHOLDER,
  before,
  fillSearchBox,
  inDialog,
  newDrive,
  newResource,
  openNewResourcePage,
  signIn,
  testFilePath,
  waitForOntologyClass,
  smoke,
} from './test-utils';

const ONTOLOGY_NAME = 'filepicker-test';

const uploadFile = async (page: Page, fileName: string) => {
  await openNewResourcePage(page);

  const fileChooserPromise = page.waitForEvent('filechooser');

  await page
    .getByRole('button', { name: 'Drop files or click here to upload.' })
    .click();

  const fileChooser = await fileChooserPromise;

  await fileChooser.setFiles(testFilePath(fileName));

  // After upload, the file's name appears in the breadcrumbs and the sidebar
  // tree at the same time. Pin to the breadcrumb so the assertion is unique.
  await expect(
    page.getByLabel('Breadcrumbs').getByText(fileName),
  ).toBeVisible();
};

// Creates an ontology with a class we can use to test the file picker.
const createModel = async (page: Page) => {
  await newResource('ontology', page);

  await inDialog(page, async (dialog, closeDialogWith) => {
    await dialog.getByPlaceholder('my-ontology').fill(ONTOLOGY_NAME);
    await closeDialogWith('Create');
  });

  await expect(page.locator(`h1:has-text("${ONTOLOGY_NAME}")`)).toBeVisible();

  await page.getByRole('button', { name: 'Add class', exact: true }).click();

  await inDialog(page, async (dialog, closeDialogWith) => {
    await dialog.getByPlaceholder('shortname').fill('robot');
    await closeDialogWith('Save');
  });

  await expect(page.locator('input[value="robot"]')).toBeVisible();

  await page.getByRole('button', { name: 'add required property' }).click();
  await page
    .getByPlaceholder(SEARCHBOX_PROPERTY_PLACEHOLDER)
    .fill('programming');

  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Enter');

  await page.getByRole('button', { name: 'Configure programming' }).click();

  await inDialog(page, async (dialog, closeDialogWith) => {
    await dialog
      .getByLabel('Datatype')
      .selectOption('https://atomicdata.dev/datatypes/atomicURL');

    await expect(dialog.getByLabel('Classtype')).not.toBeDisabled();

    await fillSearchBox(
      dialog,
      'Search for a class',
      'https://atomicdata.dev/classes/File',
      {
        label: 'Classtype',
      },
    );

    await page.keyboard.press('Enter');
    await expect(dialog.getByLabel('Classtype')).toHaveText('file');

    await closeDialogWith(DIALOG_CLOSE_BUTTON);
  });
};

test.describe('File Picker', () => {
  test.beforeEach(before);

  test(
    'select file and upload using the filepicker',
    smoke,
    async ({ page }) => {
      const SEARCH_BAR_PLACEHOLDER = 'Search or enter a URL...';

      await signIn(page);
      await newDrive(page);

      await uploadFile(page, 'testFile1.txt');
      await uploadFile(page, 'testFile2.md');

      await createModel(page);

      // `/app/new` lists classes by searching for ONTOLOGIES and rendering each
      // one's `classes` — so wait for that, not for `robot` to be findable by
      // name. The two are not the same signal, and the difference is what made
      // this test fail under suite load while passing on its own.
      await waitForOntologyClass(page, 'robot');

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

        await inDialog(page, async dialog => {
          await expect(
            dialog.getByPlaceholder(SEARCH_BAR_PLACEHOLDER),
          ).toBeVisible();
          await expect(
            dialog.getByText('Contents of test file 1'),
          ).toBeVisible();
          await expect(dialog.getByText('testFile2.md')).toBeVisible();

          await dialog.getByPlaceholder(SEARCH_BAR_PLACEHOLDER).fill('.md');

          await expect(
            dialog.getByText('Contents of test file 1'),
          ).not.toBeVisible();

          await dialog.getByRole('button', { name: 'testFile2.md' }).click();

          await expect(
            dialog.getByRole('heading', {
              name: 'first step in understanding recursion?',
            }),
          ).not.toBeVisible();
        });

        await expect(
          page
            .getByRole('region', { name: 'testFile2.md preview' })
            .getByRole('heading', {
              name: 'first step in understanding recursion?',
            }),
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

        await inDialog(page, async dialog => {
          await expect(
            dialog.getByPlaceholder(SEARCH_BAR_PLACEHOLDER),
          ).toBeVisible();

          await dialog
            .getByLabel('Upload')
            .setInputFiles(testFilePath('testFile3.txt'));
        });

        await expect(
          page
            .getByRole('region', { name: 'testFile3.txt preview' })
            .getByText('File preview not available at this time'),
        ).toBeVisible();

        await page.getByRole('button', { name: 'Save' }).click();
        await expect(page.getByText('New robot')).not.toBeVisible();
        // Read the file resource's subject from the value link in main and
        // navigate to it directly. Clicking the inline link doesn't reliably
        // trigger SPA navigation under Playwright (the browser tries to handle
        // the `did:ad:...` href as a real URL and lands on `about:blank#`).
        const fileSubject = await page
          .getByRole('main')
          .getByRole('link', { name: 'testFile3.txt' })
          .getAttribute('href');
        expect(fileSubject).toBeTruthy();
        await page.goto(
          `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(fileSubject!)}`,
        );

        // For some reason playwright will only find text with quotes in them when using a regex instead of string.
        await expect(
          page.getByText(/It's a secret to everybody/),
        ).toBeVisible();
      }
    },
  );
});
