import { test, expect, type Page } from './fixtures';
import {
  before,
  FRONTEND_URL,
  getDevDriveSecret,
  signIn,
  newDrive,
  clickAccountMenuItem,
  openAccountMenu,
  waitForSynced,
} from './test-utils';

async function addNotifications(page: Page, batchSize: number, prefix: string) {
  return page.evaluate(
    async ({ count, sourcePrefix }) => {
      const store = window.store;
      const drive = await store.getAgent()!.privateDriveSubject();
      const p = 'https://atomicdata.dev/properties/';
      const n = p;
      const created: string[] = [];

      // Independent genesis writes exercise the real inbox query, OPFS and WS.
      for (let i = 0; i < count; i++) {
        const notification = await store.newResource({
          parent: drive,
          isA: 'https://atomicdata.dev/classes/Notification',
          propVals: {
            [`${p}name`]: 'Notification test',
            [`${p}description`]: `${sourcePrefix} body ${i}`,
            ['https://atomicdata.dev/properties/about']: drive,
            [`${n}notificationSource`]: `https://example.com/${sourcePrefix}-${i}`,
            [`${n}notificationKind`]: 'chat',
            [`${n}actor`]: store.getAgent()!.subject!,
            [`${n}occurredAt`]: Date.now() + i,
          },
        });
        await notification.save();
        store.notifyResourceManuallyCreated(notification);
        created.push(notification.subject);
      }

      return created;
    },
    { count: batchSize, sourcePrefix: prefix },
  );
}

test('large inboxes deduplicate concurrent copies and isolate a different account', async ({
  page,
  browser,
}) => {
  test.slow();
  await before({ page });
  const secret = await getDevDriveSecret(page);
  await newDrive(page);
  await clickAccountMenuItem(page, 'Notifications');
  const secondContext = await browser.newContext();
  const second = await secondContext.newPage();
  await second.goto(`${FRONTEND_URL}/app/welcome`);
  await signIn(second, secret);
  await newDrive(second);
  await clickAccountMenuItem(second, 'Notifications');

  // Both copies have the same source but different signed genesis subjects.
  const copies = await Promise.all([
    addNotifications(page, 1, 'duplicate'),
    addNotifications(second, 1, 'duplicate'),
  ]);
  expect(new Set(copies.flat()).size).toBe(2);

  for (const recipient of [page, second]) {
    await expect(
      (await openAccountMenu(recipient)).getByLabel('Notifications, 1 unread'),
    ).toBeVisible();
    await recipient.keyboard.press('Escape');
  }

  await addNotifications(page, 101, 'large');

  for (const recipient of [page, second]) {
    await expect(
      (await openAccountMenu(recipient)).getByLabel(
        'Notifications, 102 unread',
      ),
    ).toBeVisible({ timeout: 30_000 });
    await recipient.keyboard.press('Escape');
    await expect(
      recipient
        .getByRole('list', { name: 'Notifications' })
        .getByRole('button')
        .first(),
    ).toContainText('102 new messages');
  }

  await page.getByRole('button', { name: 'Mark all as read' }).click();

  for (const recipient of [page, second]) {
    await expect(
      (await openAccountMenu(recipient)).getByLabel(
        /^Notifications, \d+ unread$/,
      ),
    ).toHaveCount(0, { timeout: 30_000 });
    await recipient.keyboard.press('Escape');
  }

  await waitForSynced(page);
  await second.reload();
  await expect(
    second
      .getByRole('list', { name: 'Notifications' })
      .getByRole('button')
      .first(),
  ).toContainText('102 new messages');
  await expect(second.getByLabel('Unread', { exact: true })).toHaveCount(0);

  // Obtain another identity, then actually sign out and sign in in the
  // existing recipient browser. Its cached personal inbox must disappear.
  const otherContext = await browser.newContext();
  const other = await otherContext.newPage();
  await before({ page: other });
  const otherSecret = await getDevDriveSecret(other);
  page.on('dialog', dialog => dialog.accept());
  await clickAccountMenuItem(page, 'Profile');
  await page.click('[data-test="sign-out"]');
  await page.waitForFunction(() => !window.store?.getAgent());
  await expect(
    page.getByRole('button', { name: 'Create account' }),
  ).toBeVisible();
  await signIn(page, otherSecret);
  expect(await page.evaluate(() => window.store.getAgent()?.subject)).toBe(
    await other.evaluate(() => window.store.getAgent()?.subject),
  );
  await clickAccountMenuItem(page, 'Notifications');
  await expect(page.getByText('Nothing yet.', { exact: false })).toBeVisible();
  await expect(
    page.getByRole('list', { name: 'Notifications' }).getByRole('listitem'),
  ).toHaveCount(0);
  await otherContext.close();
  await secondContext.close();
});
