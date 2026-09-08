import { test, expect } from './fixtures';
import {
  before,
  currentDriveTitle,
  devDrive,
  getCurrentSubject,
  makeDrivePublic,
  newResource,
  FRONTEND_URL,
  smoke,
} from './test-utils';

test.describe('drive deep link', () => {
  test.beforeEach(before);

  test(
    'opening a share link to a NON-DRIVE child resource adopts the PARENT drive as the session drive',
    smoke,
    async ({ page, browser }) => {
      // Context 1: create a dev drive and make it publicly readable so an
      // anonymous session can resolve it and its contents.
      await devDrive(page);
      const driveSubject = await getCurrentSubject(page);
      const driveTitle = await currentDriveTitle(page).textContent();
      expect(driveTitle).toBeTruthy();
      await makeDrivePublic(page);

      // Create a NON-DRIVE child resource inside the drive. This is the
      // resource the deep link will point at — it is NOT itself a drive, so
      // the old buggy fallback (walking an unresolvable ancestry) would adopt
      // the child as its own drive instead of its parent.
      await newResource('folder', page);
      const childSubject = await getCurrentSubject(page);

      // Sanity check: the test is meaningless if the child happens to be the
      // drive itself.
      expect(childSubject).not.toBe(driveSubject);

      // Context 2: a fresh browser profile with no stored drive, whose ENTRY
      // URL is a share deep link to the CHILD resource. The session must start
      // in the child's PARENT DRIVE, not in the child resource itself.
      const context2 = await browser.newContext();
      const page2 = await context2.newPage();
      await page2.goto(
        `${FRONTEND_URL}/app/share?subject=${encodeURIComponent(childSubject)}`,
      );

      await expect(currentDriveTitle(page2)).toHaveText(driveTitle!, {
        timeout: 20000,
      });

      // The adoption must be persisted as the session's default drive, not just
      // rendered: store.setDrive writes the localStorage entry AppSettings reads.
      // Assert it is the DRIVE subject — and explicitly NOT the child subject,
      // which is exactly what the old ancestry-fallback bug produced.
      await expect
        .poll(async () =>
          page2.evaluate(() => {
            const raw = localStorage.getItem('drive');

            return raw ? JSON.parse(raw) : undefined;
          }),
        )
        .toBe(driveSubject);

      const adoptedDrive = await page2.evaluate(() => {
        const raw = localStorage.getItem('drive');

        return raw ? JSON.parse(raw) : undefined;
      });
      expect(adoptedDrive).not.toBe(childSubject);

      await context2.close();
    },
  );

  test('opening a share link to a DRIVE itself adopts that drive as the session drive', async ({
    page,
    browser,
  }) => {
    // Context 1: create a dev drive and make it publicly readable so an
    // anonymous session can resolve it.
    await devDrive(page);
    const driveSubject = await getCurrentSubject(page);
    const driveTitle = await currentDriveTitle(page).textContent();
    expect(driveTitle).toBeTruthy();
    await makeDrivePublic(page);

    // Context 2: a fresh browser profile with no stored drive, whose ENTRY
    // URL is the share deep link to the DRIVE itself (a resource with no
    // `drive` prop, since it IS a drive root).
    const context2 = await browser.newContext();
    const page2 = await context2.newPage();
    await page2.goto(
      `${FRONTEND_URL}/app/share?subject=${encodeURIComponent(driveSubject)}`,
    );

    await expect(currentDriveTitle(page2)).toHaveText(driveTitle!, {
      timeout: 20000,
    });

    await expect
      .poll(async () =>
        page2.evaluate(() => {
          const raw = localStorage.getItem('drive');

          return raw ? JSON.parse(raw) : undefined;
        }),
      )
      .toBe(driveSubject);

    await context2.close();
  });
});
