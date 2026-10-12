/**
 * Chat messages and comments are entries in ChatLog pages, not resources of
 * their own (planning/chat-log.md). These specs drive the group chat the way a
 * person does and check what only the log changes: the message is an entry in
 * a page (`data-entry-key`), it can be edited and deleted by its author only,
 * and entries from another agent show up without a reload.
 */
import { test, expect, type Page } from './fixtures';
import {
  acceptInvite,
  before,
  editableTitle,
  FRONTEND_URL,
  getCurrentSubject,
  newResource,
  spaUrl,
  timestamp,
  topBarShareButton,
  waitForSynced,
} from './test-utils';

const chatInput = (page: Page) => page.getByLabel('Chat input');
const entry = (page: Page, text: string) =>
  page.locator('[data-entry-key]').filter({ hasText: text });

async function send(page: Page, text: string) {
  await chatInput(page).fill(text);
  await chatInput(page).press('Enter');
  await expect(entry(page, text)).toBeVisible({ timeout: 15_000 });
}

async function newChat(page: Page, title: string) {
  await newResource('chatroom', page);
  await editableTitle(page).click();
  await expect(editableTitle(page)).toHaveRole('textbox');
  await page.keyboard.press(
    process.platform === 'darwin' ? 'Meta+a' : 'Control+a',
  );
  await page.keyboard.type(title);
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: title })).toBeVisible();
}

test.describe('chat log', () => {
  test.beforeEach(before);

  test('a message is an entry; its author can edit, reply to and delete it', async ({
    page,
  }) => {
    test.slow();
    await newChat(page, 'Log Chat');

    const first = `First ${timestamp()}`;
    await send(page, first);
    const second = `Second ${timestamp()}`;
    await send(page, second);

    // Both are in the page of the log, in order, and survive a reload.
    await waitForSynced(page);
    await page.reload();
    await expect(entry(page, first)).toBeVisible({ timeout: 15_000 });
    await expect(entry(page, second)).toBeVisible();
    const keys = await page
      .locator('[data-entry-key]')
      .evaluateAll(els => els.map(el => el.getAttribute('data-entry-key')));
    expect(keys).toHaveLength(2);
    expect(keys[0]! < keys[1]!).toBe(true);

    // Edit: the text is replaced in place and marked.
    const edited = `${first} (changed)`;
    await entry(page, first).hover();
    await entry(page, first).getByTitle('Edit message').click();
    await page.getByLabel('Edit message text').fill(edited);
    await page.getByLabel('Edit message text').press('Enter');
    await expect(entry(page, edited).first()).toBeVisible();
    await expect(entry(page, edited).first()).toContainText('(edited)');

    // Reply: the new entry quotes the one it answers.
    const reply = `Reply ${timestamp()}`;
    await entry(page, edited).first().hover();
    await entry(page, edited)
      .first()
      .getByTitle('Reply to this message')
      .click();
    await chatInput(page).fill(reply);
    await chatInput(page).press('Enter');
    await expect(entry(page, reply)).toBeVisible({ timeout: 15_000 });
    await expect(entry(page, reply)).toContainText(`to Dev User: ${edited}`);

    // The reply is not sticky: the next message is a plain one.
    const plain = `Plain ${timestamp()}`;
    await send(page, plain);
    await expect(entry(page, plain)).not.toContainText('to Dev User');

    // Copy link: `<page>#<entry key>`.
    await page
      .context()
      .grantPermissions(['clipboard-read', 'clipboard-write'], {
        origin: new URL(FRONTEND_URL).origin,
      });
    await entry(page, second).hover();
    await entry(page, second).getByTitle('Copy link to this message').click();
    const key = await entry(page, second).getAttribute('data-entry-key');
    const link = await page.evaluate(() => navigator.clipboard.readText());
    expect(link).toMatch(new RegExp(`#${key}$`));

    // Delete: gone now and after a reload.
    page.once('dialog', dialog => dialog.accept());
    await entry(page, second).hover();
    await entry(page, second).getByTitle('Delete message').click();
    await expect(entry(page, second)).toHaveCount(0);
    await waitForSynced(page);
    await page.reload();
    await expect(entry(page, edited).first()).toBeVisible({ timeout: 15_000 });
    await expect(entry(page, second)).toHaveCount(0);
  });

  test('another member sees entries live and cannot change them', async ({
    page,
    browser,
    context,
  }) => {
    test.slow();
    await newChat(page, 'Shared Log');
    const hello = `Hello ${timestamp()}`;
    await send(page, hello);
    const chatSubject = await getCurrentSubject(page);

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
      await expect(entry(guest, hello)).toBeVisible({ timeout: 10_000 });
    } catch {
      // The invite may land outside the chat room.
      const chatHref = new URL('/app/show', FRONTEND_URL);
      chatHref.searchParams.set('subject', chatSubject);
      await guest.goto(chatHref.href);
      await expect(entry(guest, hello)).toBeVisible({ timeout: 20_000 });
    }

    // The owner's message is the owner's: no edit or delete for the guest.
    await entry(guest, hello).hover();
    await expect(
      entry(guest, hello).getByTitle('Reply to this message'),
    ).toBeVisible();
    await expect(entry(guest, hello).getByTitle('Edit message')).toHaveCount(0);
    await expect(entry(guest, hello).getByTitle('Delete message')).toHaveCount(
      0,
    );

    // The guest's entry reaches the owner's open chat without a reload ...
    const fromGuest = `From the guest ${timestamp()}`;
    await send(guest, fromGuest);
    await expect(entry(page, fromGuest)).toBeVisible({ timeout: 20_000 });
    // ... and so does the guest's edit of it.
    await entry(guest, fromGuest).hover();
    await entry(guest, fromGuest).getByTitle('Edit message').click();
    await guest.getByLabel('Edit message text').fill(`${fromGuest} v2`);
    await guest.getByLabel('Edit message text').press('Enter');
    await expect(entry(page, `${fromGuest} v2`)).toBeVisible({
      timeout: 20_000,
    });

    // The owner cannot rewrite the guest's entry from the UI either.
    await entry(page, `${fromGuest} v2`).hover();
    await expect(
      entry(page, `${fromGuest} v2`).getByTitle('Edit message'),
    ).toHaveCount(0);

    await guestContext.close();
  });
});
