/**
 * Notifications for new chat messages while the app is open: a toast when
 * the person is looking at the app but not at the chat, and an OS
 * notification when the app isn't focused. Each lands in the Inbox, which the
 * Notifications page lists with an unread count in the sidebar.
 *
 * Focus and visibility are stubbed too, so the runner's window layout can't
 * decide which path a notification takes.
 *
 * The OS side is observed through a stub `window.Notification`: the real one
 * needs a permission prompt, and the app itself only ever talks to that API
 * (in Tauri too, where the notification plugin provides it).
 */
import { test, expect, type Page } from './fixtures';
import {
  before,
  clickAccountMenuItem,
  currentDriveTitle,
  openAccountMenu,
  editableTitle,
  getCurrentSubject,
  newResource,
  spaUrl,
  timestamp,
  waitForSynced,
  acceptInvite,
  topBarShareButton,
  FRONTEND_URL,
} from './test-utils';

declare global {
  interface Window {
    __osNotifications?: { title: string; body?: string }[];
    __blurred?: boolean;
  }
}

const chatInput = (page: Page) => page.getByLabel('Chat input');

async function send(page: Page, text: string) {
  await chatInput(page).fill(text);
  await page.getByRole('button', { name: 'Send' }).click();
  await expect(page.getByText(text)).toBeVisible({ timeout: 15_000 });
}

test.describe('notifications', () => {
  test.beforeEach(before);

  test('a new chat message notifies the other person', async ({
    page,
    browser,
    context,
  }) => {
    test.slow();

    // Stub the OS side and let the test decide when the window has focus.
    await page.addInitScript(() => {
      window.__osNotifications = [];
      class FakeNotification {
        static permission = 'granted';
        static requestPermission = async () => 'granted';
        onclick: (() => void) | null = null;
        constructor(title: string, options?: { body?: string }) {
          window.__osNotifications!.push({ title, body: options?.body });
        }
        close() {}
      }
      // @ts-expect-error: test stand-in for the browser API
      window.Notification = FakeNotification;
      document.hasFocus = () => !window.__blurred;
      // A headless browser with a second window open can report this page
      // as hidden, which would send everything to the OS path. The test
      // decides, not the runner.
      Object.defineProperty(document, 'hidden', {
        get: () => !!window.__blurred,
      });
      Object.defineProperty(document, 'visibilityState', {
        get: () => (window.__blurred ? 'hidden' : 'visible'),
      });
    });
    await page.reload();

    await newResource('chatroom', page);
    await editableTitle(page).click();
    await page.keyboard.press(
      process.platform === 'darwin' ? 'Meta+a' : 'Control+a',
    );
    await page.keyboard.type('Notify Chat');
    await page.keyboard.press('Enter');
    await expect(
      page.getByRole('heading', { name: 'Notify Chat' }),
    ).toBeVisible();
    const hello = `Hello from the owner ${timestamp()}`;
    await send(page, hello);
    const chatSubject = await getCurrentSubject(page);

    // Invite a second person to the chat.
    await context.grantPermissions(['clipboard-read', 'clipboard-write'], {
      origin: new URL(FRONTEND_URL).origin,
    });
    await topBarShareButton(page).click();
    await page.getByLabel('Full name', { exact: true }).fill('Chat Owner');
    await page
      .getByRole('button', { name: 'Save and continue', exact: true })
      .click();
    await page
      .getByRole('radiogroup', {
        name: 'Role for people who join with the link',
      })
      .getByRole('radio', { name: 'Write' })
      .check();
    await page.getByRole('button', { name: 'Copy invite link' }).click();
    const inviteUrl = await page
      .locator('[data-invite-link]')
      .getAttribute('data-invite-link');
    expect(inviteUrl).toBeTruthy();
    await page.keyboard.press('Escape');
    await waitForSynced(page);

    const guestContext = await browser.newContext();
    const guest = await guestContext.newPage();
    await guest.goto(spaUrl(inviteUrl as string));
    await acceptInvite(guest);
    await guest.waitForURL(/\/app\//, { timeout: 15_000 });

    try {
      await expect(guest.getByText(hello)).toBeVisible({ timeout: 10_000 });
    } catch {
      // The invite may land outside the chat room.
      const chatHref = new URL('/app/show', FRONTEND_URL);
      chatHref.searchParams.set('subject', chatSubject);
      await guest.goto(chatHref.href);
      await expect(guest.getByText(hello)).toBeVisible({ timeout: 15_000 });
    }

    // The owner is in the app, but somewhere else. Navigated in-app rather
    // than by reloading, so the owner's session keeps its live connection.
    await page.getByTestId('sidebar-settings-button').click();
    await expect(
      page.getByRole('heading', { name: 'Settings', exact: true }),
    ).toBeVisible();

    const inApp = `Are you there? ${timestamp()}`;
    await send(guest, inApp);

    const toast = page.getByRole('button', { name: /in Notify Chat/ });
    await expect(toast).toBeVisible({ timeout: 20_000 });
    await expect(toast).toContainText(inApp);
    await toast.click();
    await expect(
      page.getByRole('heading', { name: 'Notify Chat' }),
    ).toBeVisible({ timeout: 15_000 });
    await expect(chatInput(page)).toBeVisible();

    // Looking at the chat itself: nothing to announce.
    const whileLooking = `You are looking ${timestamp()}`;
    await send(guest, whileLooking);
    await expect(page.getByText(whileLooking).first()).toBeVisible({
      timeout: 15_000,
    });
    await expect(
      page.getByRole('button', { name: /in Notify Chat/ }),
    ).toHaveCount(0);

    // The owner switches to another window: the OS shows it instead.
    await page.evaluate(() => (window.__blurred = true));
    const away = `Come back ${timestamp()}`;
    await send(guest, away);
    await expect
      .poll(() => page.evaluate(() => window.__osNotifications), {
        timeout: 20_000,
      })
      .toContainEqual({
        title: expect.stringContaining('Notify Chat'),
        body: away,
      });

    // Both are in the Inbox: the one opened from the toast is read, the one
    // announced while away is not.
    await page.evaluate(() => (window.__blurred = false));
    await clickAccountMenuItem(page, 'Notifications');
    const list = page.getByRole('list', { name: 'Notifications' });
    await expect(list.getByRole('listitem')).toHaveCount(2, {
      timeout: 30_000,
    });
    await expect(
      (await openAccountMenu(page)).getByLabel('Notifications, 1 unread'),
    ).toBeVisible();
    await page.keyboard.press('Escape');
    const awayItem = list.getByRole('button', { name: new RegExp(away) });
    await expect(awayItem.getByLabel('Unread')).toBeVisible();
    await expect(
      list
        .getByRole('button', { name: new RegExp(inApp) })
        .getByLabel('Unread'),
    ).toHaveCount(0);

    await page.getByRole('button', { name: 'Mark all as read' }).click();
    await expect(awayItem.getByLabel('Unread')).toHaveCount(0);
    const menu = await openAccountMenu(page);
    await expect(
      menu.getByRole('menuitem', { name: /^Notifications\b/ }),
    ).toBeVisible();
    await expect(menu.getByLabel(/^Notifications, \d+ unread$/)).toHaveCount(0);
    await page.keyboard.press('Escape');

    await awayItem.click();
    await expect(
      page.getByRole('heading', { name: 'Notify Chat' }),
    ).toBeVisible({ timeout: 15_000 });

    await guestContext.close();
  });

  test('a reply and a comment on something you made notify you', async ({
    page,
    browser,
    context,
  }) => {
    test.slow();

    await page.addInitScript(() => {
      document.hasFocus = () => true;
      Object.defineProperty(document, 'hidden', { get: () => false });
      Object.defineProperty(document, 'visibilityState', {
        get: () => 'visible',
      });
    });
    await page.reload();

    await newResource('folder', page);
    await editableTitle(page).click();
    await page.keyboard.press(
      process.platform === 'darwin' ? 'Meta+a' : 'Control+a',
    );
    await page.keyboard.type('Comment Folder');
    await page.keyboard.press('Enter');
    await expect(
      page.getByRole('heading', { name: 'Comment Folder' }),
    ).toBeVisible();
    const folderSubject = await getCurrentSubject(page);

    // The owner leaves the first remark in the folder's comments.
    await page.getByTestId('navbar-comments-button').click();
    const remark = `Owner remark ${timestamp()}`;
    const panelInput = page
      .getByTestId('comments-panel')
      .getByLabel('Chat input');
    await panelInput.fill(remark);
    await panelInput.press('Enter');
    await expect(
      page.getByTestId('comments-panel').getByText(remark),
    ).toBeVisible({ timeout: 15_000 });

    await context.grantPermissions(['clipboard-read', 'clipboard-write'], {
      origin: new URL(FRONTEND_URL).origin,
    });
    // Comments live in the drive's Comments folder, so whoever is to see and
    // add them is invited to the drive, not to the folder alone.
    await currentDriveTitle(page).click();
    await expect(
      page.getByRole('heading', { name: 'Comment Folder' }),
    ).toHaveCount(0);
    await topBarShareButton(page).click();
    await page.getByLabel('Full name', { exact: true }).fill('Folder Owner');
    await page
      .getByRole('button', { name: 'Save and continue', exact: true })
      .click();
    await page
      .getByRole('radiogroup', {
        name: 'Role for people who join with the link',
      })
      .getByRole('radio', { name: 'Write' })
      .check();
    await page.getByRole('button', { name: 'Copy invite link' }).click();
    const inviteUrl = await page
      .locator('[data-invite-link]')
      .getAttribute('data-invite-link');
    expect(inviteUrl).toBeTruthy();
    await page.keyboard.press('Escape');
    await waitForSynced(page);

    const guestContext = await browser.newContext();
    const guest = await guestContext.newPage();
    await guest.goto(spaUrl(inviteUrl as string));
    await acceptInvite(guest);
    await guest.waitForURL(/\/app\//, { timeout: 15_000 });

    const folderHref = new URL('/app/show', FRONTEND_URL);
    folderHref.searchParams.set('subject', folderSubject);
    await guest.goto(folderHref.href);

    // The guest has not opened the thread yet: it is counted and unseen.
    const guestButton = guest.getByTestId('navbar-comments-button');
    await expect(guestButton).toHaveAttribute('data-unseen', '', {
      timeout: 20_000,
    });
    await expect(guestButton).toContainText('1');
    await guestButton.click();
    const guestPanel = guest.getByTestId('comments-panel');
    await expect(guestPanel.getByText(remark)).toBeVisible({ timeout: 15_000 });
    await expect(guestButton).not.toHaveAttribute('data-unseen', '');

    // The owner is somewhere else in the app.
    await page.getByTestId('sidebar-settings-button').click();
    await expect(
      page.getByRole('heading', { name: 'Settings', exact: true }),
    ).toBeVisible();

    // A reply to the owner's remark ...
    await guestPanel
      .locator('[data-entry-key]')
      .filter({ hasText: remark })
      .hover();
    await guestPanel
      .locator('[data-entry-key]')
      .filter({ hasText: remark })
      .getByTitle('Reply to this message')
      .click();
    const replyText = `Guest reply ${timestamp()}`;
    await guestPanel.getByLabel('Chat input').fill(replyText);
    await guestPanel.getByLabel('Chat input').press('Enter');
    await expect(guestPanel.getByText(replyText)).toBeVisible({
      timeout: 15_000,
    });
    const replied = page.getByRole('button', { name: /replied to you/ });
    await expect(replied).toBeVisible({ timeout: 20_000 });
    await expect(replied).toContainText(replyText);
    await replied.click();
    await expect(
      page.getByRole('heading', { name: 'Comment Folder' }),
    ).toBeVisible({ timeout: 15_000 });

    // ... and a plain comment, once the owner has gone elsewhere again.
    await page.getByTestId('sidebar-settings-button').click();
    await expect(
      page.getByRole('heading', { name: 'Settings', exact: true }),
    ).toBeVisible();
    const note = `Guest note ${timestamp()}`;
    await guestPanel.getByLabel('Chat input').fill(note);
    await guestPanel.getByLabel('Chat input').press('Enter');
    const commented = page.getByRole('button', {
      name: /commented on Comment Folder/,
    });
    await expect(commented).toBeVisible({ timeout: 20_000 });
    await expect(commented).toContainText(note);

    // The owner's own comments never notify the owner.
    await expect(
      page.getByRole('button', { name: new RegExp(remark) }),
    ).toHaveCount(0);

    await guestContext.close();
  });
});
