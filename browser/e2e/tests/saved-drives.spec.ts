import { test, expect } from './fixtures';
import { before, newDrive, openConfigureDrive } from './test-utils';

/**
 * A drive you make is one of your drives.
 *
 * The list lives on the user's private drive as its `drives` array, and
 * `createDrive` is supposed to append to it. Nothing asserted that it did: the
 * suite has several tests that create a drive, but they create one in order to
 * work in it, and the one test that opens this page checks that the headings
 * are there rather than what is under them. A drive that is created, navigated
 * to, and then dropped from the profile passes all of them.
 */
test.describe('saved drives', () => {
  test.beforeEach(before);

  test('a drive you create is listed among your drives', async ({ page }) => {
    const { driveTitle } = await newDrive(page);

    await openConfigureDrive(page);

    // Scoped to the list itself, not the page: the drive's own name is in the
    // breadcrumb and the switcher too, and an unscoped match would pass on
    // chrome that says nothing about whether the list was ever written.
    await expect(
      page.getByRole('heading', { name: 'My drives' }),
    ).toBeVisible();
    await expect(
      page.getByTestId('my-drives').getByText(driveTitle),
    ).toBeVisible();
  });

  test('and it is still there after a reload', async ({ page }) => {
    const { driveTitle } = await newDrive(page);

    // The write that records it resolves locally before the commit reaches the
    // server, so being on screen a moment after creation proves nothing. A
    // reload is what asks whether it was actually persisted.
    await page.reload();
    await openConfigureDrive(page);

    await expect(
      page.getByTestId('my-drives').getByText(driveTitle),
    ).toBeVisible({ timeout: 15000 });
  });

  test('a second drive, made after a reload, is listed too', async ({
    page,
  }) => {
    const { driveTitle: first } = await newDrive(page);

    // The list lives on the private drive, and recording a new drive needs
    // that resource in hand. Right after sign-in it is already in memory,
    // which is the only state the other tests here exercise. A reload empties
    // the store, so this is the ordinary case for anyone who made their
    // account on a previous day.
    await page.reload();

    const { driveTitle: second } = await newDrive(page);

    await openConfigureDrive(page);

    const myDrives = page.getByTestId('my-drives');
    await expect(myDrives.getByText(second)).toBeVisible({ timeout: 15000 });
    await expect(myDrives.getByText(first)).toBeVisible();
  });
});
