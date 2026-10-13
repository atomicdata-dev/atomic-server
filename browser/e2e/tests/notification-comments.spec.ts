import { test, expect } from './fixtures';
import {
  before,
  FRONTEND_URL,
  getDevDriveSecret,
  signIn,
  newDrive,
  newResource,
  getCurrentSubject,
  clickAccountMenuItem,
  topBarShareButton,
  acceptInvite,
  spaUrl,
  waitForSynced,
} from './test-utils';

test('comments and replies sync to another inbox and open the comment thread', async ({
  page,
  browser,
  context,
}) => {
  test.slow();
  await before({ page });
  const secret = await getDevDriveSecret(page);
  await newDrive(page);
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], {
    origin: new URL(FRONTEND_URL).origin,
  });
  await topBarShareButton(page).click();
  await page.getByLabel('Full name', { exact: true }).fill('Comment Owner');
  await page
    .getByRole('button', { name: 'Save and continue', exact: true })
    .click();
  await page
    .getByRole('radiogroup', { name: 'Role for people who join with the link' })
    .getByRole('radio', { name: 'Write' })
    .check();
  await page.getByRole('button', { name: 'Copy invite link' }).click();
  const invite = await page.evaluate(() => navigator.clipboard.readText());
  await page.keyboard.press('Escape');
  await newResource('document', page);
  const document = await getCurrentSubject(page);
  await page.getByTestId('navbar-comments-button').click();
  const panel = page.getByTestId('comments-panel');
  const input = panel.getByLabel('Chat input');
  await input.fill('Owner thread starter');
  await input.press('Enter');
  await expect(panel.getByText('Owner thread starter').first()).toBeVisible();
  await waitForSynced(page);
  await clickAccountMenuItem(page, 'Notifications');

  const secondContext = await browser.newContext();
  const second = await secondContext.newPage();
  await second.goto(`${FRONTEND_URL}/app/welcome`);
  await signIn(second, secret);
  await newDrive(second);
  await clickAccountMenuItem(second, 'Notifications');
  const guestContext = await browser.newContext();
  const guest = await guestContext.newPage();
  await guest.goto(spaUrl(invite));
  await acceptInvite(guest);
  await guest.goto(
    `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(document)}`,
  );
  await guest.getByTestId('navbar-comments-button').click();
  const guestPanel = guest.getByTestId('comments-panel');
  await expect(
    guestPanel.getByText('Owner thread starter').first(),
  ).toBeVisible();
  const guestInput = guestPanel.getByLabel('Chat input');
  await guestInput.fill('Comment from collaborator');
  await guestInput.press('Enter');

  for (const recipient of [page, second]) {
    const item = recipient
      .getByRole('list', { name: 'Notifications' })
      .getByRole('button', { name: /Comment from collaborator/ });
    await expect(item.getByLabel('Unread')).toBeVisible({ timeout: 30_000 });
  }

  await guestPanel.getByTitle('Reply to this message').first().click();
  await guestInput.fill('Reply to owner comment');
  await guestInput.press('Enter');
  const reply = second
    .getByRole('list', { name: 'Notifications' })
    .getByRole('button', { name: /Reply to owner comment/ });
  await expect(reply.getByLabel('Unread')).toBeVisible({ timeout: 30_000 });
  await reply.click();
  await expect(second.getByTestId('comments-panel')).toHaveAttribute(
    'data-open',
    '',
  );
  await expect(
    second
      .getByTestId('comments-panel')
      .getByText('Reply to owner comment')
      .first(),
  ).toBeVisible();
  await expect(
    page
      .getByRole('list', { name: 'Notifications' })
      .getByRole('button', { name: /Reply to owner comment/ })
      .getByLabel('Unread'),
  ).toHaveCount(0, { timeout: 30_000 });
  await guestContext.close();
  await secondContext.close();
});
