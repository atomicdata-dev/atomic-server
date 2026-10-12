/**
 * Existing chat messages move into the chat log (planning/chat-log.md,
 * "Existing messages"). The moving itself is done by the store when it opens
 * (the Rust tests in lib/src/db/chat_migration_test.rs cover it); these specs
 * cover what a person sees:
 *
 * - old `Message` resources, made through the old path, still show;
 * - once their entries exist in a page (what the migration writes, with the
 *   deterministic key) the same chat shows each message once, also for a stale
 *   copy of the old resource that is still around;
 * - a message that has no entry yet is still listed.
 */
import { migratedEntryKey } from '@tomic/lib';
import { test, expect, type Page } from './fixtures';
import {
  before,
  editableTitle,
  getCurrentSubject,
  newResource,
  timestamp,
  waitForSynced,
} from './test-utils';

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

test.describe('chat log migration', () => {
  test.beforeEach(before);

  test('old messages show once, whether or not their entry exists', async ({
    page,
  }) => {
    test.slow();
    await newChat(page, 'Old Chat');
    const chat = await getCurrentSubject(page);
    const stamp = timestamp();
    const texts = [
      `old one ${stamp}`,
      `old two ${stamp}`,
      `old three ${stamp}`,
    ];

    // Messages the way the app wrote them before the log: a resource each.
    const made = await page.evaluate(
      async ({ chat: parent, texts: lines }) => {
        const out: { subject: string; createdAt: number; author: string }[] =
          [];

        for (const text of lines) {
          const resource = await window.store.newResource({
            parent,
            isA: ['https://atomicdata.dev/classes/Message'],
            propVals: {
              'https://atomicdata.dev/properties/description': text,
            },
          });
          await resource.save();
          out.push({
            subject: resource.subject,
            createdAt: resource.getCreatedAt() ?? 0,
            author: window.store.getAgent()?.subject ?? '',
          });
          await new Promise(resolve => setTimeout(resolve, 5));
        }

        return out;
      },
      { chat, texts },
    );
    await waitForSynced(page);
    await page.reload();

    for (const text of texts) {
      await expect(page.getByText(text, { exact: true })).toHaveCount(1, {
        timeout: 15_000,
      });
    }

    // Nothing in the chat is an entry yet.
    await expect(page.locator('[data-entry-key]')).toHaveCount(0);

    // What the migration writes for the first two: one page, deterministic keys.
    await page.evaluate(
      async ({ chat: parent, entries }) => {
        const log = await window.store.newResource({
          parent,
          isA: 'https://atomicdata.dev/classes/ChatLog',
        });

        for (const e of entries) {
          log.putChatLogEntry(e.key, {
            a: e.author,
            t: e.text,
            c: e.createdAt,
          });
        }

        await log.save();
        window.store.notifyResourceManuallyCreated(log);
      },
      {
        chat,
        entries: made.slice(0, 2).map((m, i) => ({
          key: migratedEntryKey(m.createdAt, m.subject),
          author: m.author,
          text: texts[i] as string,
          createdAt: m.createdAt,
        })),
      },
    );
    await waitForSynced(page);
    await page.reload();

    // Each text is on screen exactly once. The first two are entries now; the
    // stale `Message` resources behind them are hidden, the third has no
    // entry and is still listed as it was.
    for (const text of texts) {
      await expect(page.getByText(text, { exact: true })).toHaveCount(1, {
        timeout: 15_000,
      });
    }

    await expect(page.locator('[data-entry-key]')).toHaveCount(2);
    await expect(
      page.locator('[data-entry-key]').filter({ hasText: texts[0] }),
    ).toHaveCount(1);
    await expect(
      page.locator('[data-entry-key]').filter({ hasText: texts[1] }),
    ).toHaveCount(1);
    await expect(
      page.locator('[data-entry-key]').filter({ hasText: texts[2] }),
    ).toHaveCount(0);

    // Order is by time: one, two, three.
    const order = await page
      .getByText(new RegExp(`^old (one|two|three) ${stamp}$`))
      .allTextContents();
    expect(order).toEqual(texts);

    // A new message goes into the log next to them.
    const fresh = `new one ${stamp}`;
    await page.getByLabel('Chat input').fill(fresh);
    await page.getByLabel('Chat input').press('Enter');
    await expect(
      page.locator('[data-entry-key]').filter({ hasText: fresh }),
    ).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText(fresh, { exact: true })).toHaveCount(1);
  });
});
