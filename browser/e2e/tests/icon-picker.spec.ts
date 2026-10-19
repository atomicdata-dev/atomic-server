import { test, expect, type Page } from './fixtures';
import {
  before,
  currentDialog,
  editableTitle,
  newDrive,
  newResource,
  openNewResourcePage,
  waitForSynced,
} from './test-utils';

/**
 * One icon picker, three entry points: the title icon, the "Add icon" hover
 * affordance and the More menu. "Pick existing" used to do nothing when the
 * picker was opened from an icon that was already set, because the file
 * picker was handed to a popover that was closing.
 */

const svg = (fill: string) =>
  Buffer.from(
    `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64"><rect width="64" height="64" fill="${fill}"/></svg>`,
  );

/** Uploads an image to the drive, so there is an existing File to pick. */
async function uploadImage(page: Page, name: string, fill: string) {
  await openNewResourcePage(page);

  const chooser = page.waitForEvent('filechooser');
  await page
    .getByRole('button', { name: 'Drop files or click here to upload.' })
    .click();
  await (
    await chooser
  ).setFiles({ name, mimeType: 'image/svg+xml', buffer: svg(fill) });
  await expect(page.getByLabel('Breadcrumbs').getByText(name)).toBeVisible();
  await waitForSynced(page);
}

const titleImage = (page: Page) => editableTitle(page).locator('img');

/** The picker dialog, once "Pick existing" has opened the file search. */
async function pickExisting(page: Page, fileName: string) {
  await currentDialog(page)
    .getByRole('button', { name: 'Pick existing' })
    .click();
  await expect(page.getByPlaceholder('Search or enter a URL...')).toBeVisible();
  await currentDialog(page).getByRole('button', { name: fileName }).click();
  await expect(page.getByPlaceholder('Search or enter a URL...')).toBeHidden();
}

async function openFromMoreMenu(page: Page) {
  await page.locator('[data-test="context-menu"]').click();
  // On desktop the inline title buttons cover this action, so the menu lists
  // it only when searched for.
  await page.getByRole('textbox', { name: 'Filter actions' }).fill('icon');
  await page
    .getByRole('menuitem', { name: /^(Add|Change) icon/ })
    .first()
    .click();
}

async function iconSrc(page: Page) {
  await expect(titleImage(page)).toBeVisible();

  return titleImage(page).getAttribute('src');
}

test.describe('icon picker', { tag: '@icons' }, () => {
  test.beforeEach(before);

  test('drive page: "Add icon" and the title icon open the same picker', async ({
    page,
  }) => {
    test.slow();
    // Not the private dev drive: its title is locked, and a title that can be
    // edited is what swallowed the file picker.
    await newDrive(page);
    const driveUrl = page.url();
    await uploadImage(page, 'icon-a.svg', 'red');
    await uploadImage(page, 'icon-b.svg', 'blue');
    await page.goto(driveUrl);

    // Entry point: the "Add icon" hover affordance.
    await editableTitle(page).hover();
    await page.getByRole('button', { name: 'Add icon' }).click();
    await expect(
      currentDialog(page).getByRole('heading', { name: 'Icon' }),
    ).toBeVisible();
    await pickExisting(page, 'icon-a.svg');
    const first = await iconSrc(page);

    // Entry point: the icon that is now in the title. This is the reported bug.
    await editableTitle(page)
      .getByRole('button', { name: 'Change icon' })
      .click();
    await expect(
      currentDialog(page).getByRole('heading', { name: 'Icon' }),
    ).toBeVisible();
    await pickExisting(page, 'icon-b.svg');
    await expect.poll(() => iconSrc(page)).not.toBe(first);

    // Clicking the icon must not have flipped the title into its editor.
    await expect(
      page.locator('textarea[data-testid="editable-title"]'),
    ).toHaveCount(0);

    // Remove clears the icon.
    await editableTitle(page)
      .getByRole('button', { name: 'Change icon' })
      .click();
    await currentDialog(page)
      .getByRole('button', { name: 'Remove icon' })
      .click();
    await expect(titleImage(page)).toHaveCount(0);
  });

  test('resource page: title icon and the More menu pick an existing file', async ({
    page,
  }) => {
    test.slow();
    await uploadImage(page, 'icon-a.svg', 'red');
    await uploadImage(page, 'icon-b.svg', 'blue');
    await newResource('folder', page);
    await expect(page.getByTestId('editable-title')).toBeVisible();

    // Entry point: the More menu.
    await openFromMoreMenu(page);
    await pickExisting(page, 'icon-a.svg');
    const first = await iconSrc(page);

    // Entry point: the title icon.
    await editableTitle(page)
      .getByRole('button', { name: 'Change icon' })
      .click();
    await pickExisting(page, 'icon-b.svg');
    await expect.poll(() => iconSrc(page)).not.toBe(first);

    // The More menu offers the same dialog, with Remove.
    await openFromMoreMenu(page);
    await currentDialog(page)
      .getByRole('button', { name: 'Remove icon' })
      .click();
    await expect(titleImage(page)).toHaveCount(0);
  });
});
