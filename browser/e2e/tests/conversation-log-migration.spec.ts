/**
 * Direct messages move into the chat log (planning/chat-log.md, "Step 4:
 * direct messages"). The moving itself is done by the store when it opens (the
 * Rust tests in lib/src/db/conversation_migration_test.rs cover it); this spec
 * covers what a person sees in a conversation:
 *
 * - old `SealedMessage` resources, made through the old path, still open and
 *   show once;
 * - once the entries of some of them exist in a page (what the migration
 *   writes: the same sealed payload under the deterministic key) a stale copy
 *   of the old resource is not shown twice, and the one without an entry is
 *   still listed, in order;
 * - a new message goes into the log next to them.
 */
import { conversations, migratedEntryKey } from '@tomic/lib';
import { test, expect, type Page } from './fixtures';
import {
  before,
  devDrive,
  getCurrentSubject,
  installCommitWatcher,
  SERVER_URL,
  timestamp,
  waitForSynced,
} from './test-utils';

async function agentSubject(page: Page): Promise<string> {
  await page.waitForFunction(() => !!window.store?.getAgent()?.subject);

  return page.evaluate(() => window.store.getAgent()!.subject!);
}

async function waitForEncryptionKey(agent: string) {
  await expect
    .poll(
      async () => {
        const res = await fetch(`${SERVER_URL}/${agent}`, {
          headers: { Accept: 'application/ad+json' },
        }).catch(() => undefined);

        if (!res?.ok) return false;

        return (await res.text()).includes('encryptionKey');
      },
      { timeout: 30_000 },
    )
    .toBe(true);
}

async function send(page: Page, text: string) {
  await page.getByLabel('Chat input').fill(text);
  await page.getByRole('button', { name: 'Send' }).click();
  await expect(page.getByText(text, { exact: true })).toBeVisible({
    timeout: 15_000,
  });
}

test.describe('conversation log migration', () => {
  test.beforeEach(before);

  test('old direct messages show once, whether or not their entry exists, and new ones are entries', async ({
    page,
    browser,
  }) => {
    test.slow();

    const bobContext = await browser.newContext();
    const bob = await bobContext.newPage();
    await installCommitWatcher(bob);
    await devDrive(bob);
    const bobSubject = await agentSubject(bob);
    await waitForEncryptionKey(bobSubject);

    await page.getByTestId('new-message').click();
    await page.getByLabel('Who').fill(bobSubject);
    await page.getByRole('button', { name: 'Start conversation' }).click();
    await expect(page.getByText('End-to-end encrypted')).toBeVisible({
      timeout: 30_000,
    });
    const conversation = await getCurrentSubject(page);
    const stamp = timestamp();
    const texts = [
      `old one ${stamp}`,
      `old two ${stamp}`,
      `old three ${stamp}`,
    ];

    for (const text of texts) {
      await send(page, text);
    }

    await expect(page.locator('[data-entry-key]')).toHaveCount(3);

    // Turn them into what the app wrote before the log: take the sealed payload
    // out of each entry, remove the entry, and store it as a SealedMessage
    // resource of its own, with `write` limited to its author.
    const made = await page.evaluate(
      async ({ conversation: subject, classes, props }) => {
        const store = window.store;
        const me = store.getAgent()?.subject ?? '';
        const conv = await store.getResource(subject);
        const children = await conv.getChildrenCollection();
        await children.waitForReady();
        const sealed: { s: string; c: number }[] = [];

        for (let i = 0; i < children.totalMembers; i++) {
          const member = await children.getMemberWithIndex(i);
          const child = member ? await store.getResource(member) : undefined;

          if (!child?.hasClasses(classes.log)) continue;

          for (const { key, entry } of child.listChatLogEntries()) {
            sealed.push({ s: entry.s as string, c: entry.c });
            child.removeChatLogEntry(key);
          }

          await child.save();
        }

        sealed.sort((a, b) => a.c - b.c);
        const out: { subject: string; createdAt: number; s: string }[] = [];

        for (const item of sealed) {
          const resource = await store.newResource({
            parent: subject,
            isA: classes.message,
            propVals: { [props.sealed]: item.s, [props.write]: [me] },
          });
          await resource.save();
          store.notifyResourceManuallyCreated(resource);
          out.push({
            subject: resource.subject,
            createdAt: resource.getCreatedAt() ?? 0,
            s: item.s,
          });
          await new Promise(resolve => setTimeout(resolve, 5));
        }

        return { me, messages: out };
      },
      {
        conversation,
        classes: {
          log: 'https://atomicdata.dev/classes/ChatLog',
          message: conversations.classes.sealedMessage,
        },
        props: {
          sealed: conversations.properties.sealed,
          write: 'https://atomicdata.dev/properties/write',
        },
      },
    );
    expect(made.messages).toHaveLength(3);
    await waitForSynced(page);
    await page.reload();

    // The old resources open and show once; nothing is an entry yet.
    for (const text of texts) {
      await expect(page.getByText(text, { exact: true })).toHaveCount(1, {
        timeout: 20_000,
      });
    }

    await expect(page.locator('[data-entry-key]')).toHaveCount(0);

    // What the migration writes for the first two: one page under the
    // conversation, the same payload, the deterministic key.
    await page.evaluate(
      async ({ conversation: subject, entries, me }) => {
        const store = window.store;
        const log = await store.newResource({
          parent: subject,
          isA: 'https://atomicdata.dev/classes/ChatLog',
        });

        for (const e of entries) {
          log.putChatLogEntry(e.key, { a: me, t: '', c: e.createdAt, s: e.s });
        }

        await log.save();
        store.notifyResourceManuallyCreated(log);
      },
      {
        conversation,
        me: made.me,
        entries: made.messages.slice(0, 2).map(m => ({
          key: migratedEntryKey(m.createdAt, m.subject),
          createdAt: m.createdAt,
          s: m.s,
        })),
      },
    );
    await waitForSynced(page);
    await page.reload();

    // Each text is on screen once and in order: the first two are entries (the
    // stale resources behind them are hidden), the third is still a resource.
    for (const text of texts) {
      await expect(page.getByText(text, { exact: true })).toHaveCount(1, {
        timeout: 20_000,
      });
    }

    await expect(page.locator('[data-entry-key]')).toHaveCount(2);
    await expect(
      page.locator('[data-entry-key]').filter({ hasText: texts[2] }),
    ).toHaveCount(0);
    const order = await page
      .getByText(new RegExp(`^old (one|two|three) ${stamp}$`))
      .allTextContents();
    expect(order).toEqual(texts);

    // A new message goes into the log next to them, and Bob reads all of it.
    const fresh = `new one ${stamp}`;
    await send(page, fresh);
    await expect(
      page.locator('[data-entry-key]').filter({ hasText: fresh }),
    ).toBeVisible();

    await bob.reload();
    await bob.getByTestId('conversation-item').first().click();
    await expect(bob.getByText(fresh, { exact: true })).toBeVisible({
      timeout: 30_000,
    });
    await expect(bob.getByText(texts[0], { exact: true })).toBeVisible();
    await expect(bob.getByText(texts[2], { exact: true })).toBeVisible();

    await bobContext.close();
  });
});
