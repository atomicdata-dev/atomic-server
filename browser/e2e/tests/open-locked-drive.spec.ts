import { test, expect } from '@playwright/test';
import {
  before,
  clickAccountMenuItem,
  getCurrentSubject,
  FRONTEND_URL,
} from './test-utils';

test.describe('open-locked-drive', () => {
  test('a drive opened signed out through the portal Open link lands on the sign-in step', async ({
    page,
    context,
  }) => {
    await before({ page });
    const drive = await getCurrentSubject(page);

    page.on('dialog', dialog => dialog.accept());
    await clickAccountMenuItem(page, 'Profile');
    await page.click('[data-test="sign-out"]');
    await expect(
      page.getByRole('button', { name: 'Get started' }),
    ).toBeVisible();

    // The portal's Open action carries the drive twice: as the subject and as
    // the explicit workspace selection. Consuming the latter used to undo the
    // redirect to the sign-in step, leaving the visitor on the error page.
    const popup = await context.newPage();
    await popup.goto(
      `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(drive)}&drive=${encodeURIComponent(drive)}`,
    );

    await expect(popup).toHaveURL(/\/app\/welcome\?next=/, { timeout: 10_000 });
  });
});
