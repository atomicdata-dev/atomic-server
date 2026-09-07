/**
 * Comments: any resource can get a comment thread via the Comments panel.
 *
 * Comments are plain Message resources created client-side (normal signed
 * commits, offline-capable): `about` points at the commented resource and
 * defines the thread, `parent` is the drive's Comments folder (a standard
 * location created lazily on the first comment).
 *
 * Covers the full loop:
 *   1. The panel shows the chat composer immediately; the first send creates
 *      the Comments folder + the comment, no setup step.
 *   2. The parent folder shows a comment-count badge fed by a live
 *      collection query on `about`.
 *   3. The unseen state is device-local: clearing it marks the badge unseen.
 */

import { test, expect } from './fixtures';
import {
  before,
  FRONTEND_URL,
  getCurrentSubject,
  newResource,
} from './test-utils';

const COMMENTS = ['First comment!', 'Second comment!'] as const;

test.describe('discussion comments', () => {
  test.beforeEach(before);

  test('start discussion, post messages, live badge with unseen state', async ({
    page,
  }) => {
    test.slow();

    // A folder to hold the commented resource, so we can assert its badge.
    await newResource('folder', page);
    await page.keyboard.type('Badge Folder');
    await page.keyboard.press('Enter');
    await expect(
      page.getByRole('heading', { name: 'Badge Folder' }),
    ).toBeVisible({ timeout: 10000 });
    const folderSubject = await getCurrentSubject(page);

    // The commented resource, created INSIDE Badge Folder via the folder
    // page's quick-create row so the badge assertion below can find it in
    // the folder's listing. Any class works; a folder keeps the flow simple.
    await page
      .getByRole('main')
      .getByRole('button', { name: 'New Folder' })
      .click();
    await page.waitForURL(
      url => {
        const s = new URLSearchParams(url.search).get('subject');

        return !!s && s !== folderSubject;
      },
      { timeout: 15000 },
    );

    // Open the Comments panel. The chat composer shows immediately; the
    // Comments folder and first comment are created on the first send.
    await page.getByTestId('navbar-comments-button').click();
    const panel = page.getByTestId('comments-panel');
    await expect(panel).toBeVisible();
    const chatInput = panel.getByLabel('Chat input');
    await expect(chatInput).toBeVisible({ timeout: 15000 });

    for (const text of COMMENTS) {
      await chatInput.fill(text);
      await chatInput.press('Enter');
      await expect(chatInput).toHaveValue('');
      await expect(panel.locator(`text=${text}`).first()).toBeVisible({
        timeout: 10000,
      });
    }

    // The folder view shows the count badge, fed by a collection query on
    // `about` — this asserts the comments were persisted and indexed.
    await page.goto(
      `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(folderSubject)}`,
    );
    const badge = page.getByTestId('comment-count-badge');
    await expect(badge).toBeVisible({ timeout: 15000 });
    await expect(badge).toHaveText(String(COMMENTS.length), {
      timeout: 15000,
    });

    // The panel was open while posting, so everything is seen on this device.
    await expect(badge).not.toHaveAttribute('data-unseen');

    // Wipe the device-local lastSeen state: the badge must flip to unseen.
    await page.evaluate(() =>
      window.localStorage.removeItem('atomic.comments.lastSeen'),
    );
    await page.reload();
    const badgeAfterReload = page.getByTestId('comment-count-badge');
    await expect(badgeAfterReload).toBeVisible({ timeout: 15000 });
    await expect(badgeAfterReload).toHaveAttribute('data-unseen', '');
  });
});
