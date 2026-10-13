/**
 * AI chats move into the chat log (planning/chat-log.md, "AI chat"). The
 * moving itself is done by the store when it opens (the Rust tests in
 * lib/src/db/ai_chat_migration_test.rs cover it); these specs cover what a
 * person sees:
 *
 * - an old chat (an `ai-message` resource per message, a resource per part, a
 *   `messages` list on the chat) still opens and shows every message once;
 * - once the entries of some messages exist in a page (what the migration
 *   writes, with the deterministic key), a stale copy of the old resource is
 *   not shown twice, and the one without an entry is still listed, in order;
 * - a new message and its reply go into the log: one page next to the chat,
 *   no new `ai-message` resources, and they come back after a reload.
 */
import { ai, core, isAtomicIdentifier, migratedEntryKey } from '@tomic/lib';
import { test, expect } from './fixtures';
import { before, timestamp, waitForSynced } from './test-utils';
import {
  enableAIForTesting,
  sendChatMessage,
  setupAIRouteMocks,
} from './ai-mock';

const MOCK_RESPONSE = 'This is a mock AI response.';

test.describe('AI chat log migration', () => {
  test.beforeEach(async ({ page }) => {
    await setupAIRouteMocks(page, { chatResponse: MOCK_RESPONSE });
    await enableAIForTesting(page);
    await before({ page });
  });

  test('an old chat shows once, whether or not its entries exist, and new messages are entries', async ({
    page,
  }) => {
    test.slow();
    const stamp = timestamp();
    const title = `Old AI chat ${stamp}`;
    const lines = [
      { role: 'user', text: `old question ${stamp}` },
      { role: 'assistant', text: `old answer ${stamp}` },
      { role: 'user', text: `old follow-up ${stamp}` },
    ];

    // The way the app wrote a chat before the log.
    const made = await page.evaluate(
      async ({ classes, props, name, title: chatTitle, lines: input }) => {
        const store = window.store;
        const drive = await store.privateDriveSubject();
        const chat = await store.newResource({
          parent: drive,
          isA: classes.chat,
          propVals: { [name]: chatTitle },
        });
        await chat.save();
        store.notifyResourceManuallyCreated(chat);
        const out: { subject: string; createdAt: number }[] = [];
        const subjects: string[] = [];

        for (const line of input) {
          const message = await store.newResource({
            isA: classes.message,
            parent: chat.subject,
            propVals: {
              [props.role]: `https://atomicdata.dev/01jtjxtsa9syxmfca2zx5gcnmj/tag/${line.role}`,
              [props.parts]: [],
            },
          });
          const part = await store.newResource({
            isA: classes.text,
            parent: message.subject,
            propVals: { [props.description]: line.text },
          });
          await part.save();
          await message.set(props.parts, [part.subject]);
          await message.save();
          subjects.push(message.subject);
          out.push({
            subject: message.subject,
            createdAt: message.getCreatedAt() ?? 0,
          });
          await new Promise(resolve => setTimeout(resolve, 5));
        }

        await chat.set(props.messages, subjects);
        await chat.save();

        return { chat: chat.subject, messages: out };
      },
      {
        classes: {
          chat: ai.classes.aiChat,
          message: ai.classes.aiMessage,
          text: ai.classes.textPart,
        },
        props: {
          role: ai.properties.role,
          parts: ai.properties.parts,
          messages: ai.properties.messages,
          description: core.properties.description,
        },
        name: core.properties.name,
        title,
        lines,
      },
    );
    await waitForSynced(page);

    const open = async () => {
      await page.goto(
        `${new URL(page.url()).origin}/app/show?subject=${encodeURIComponent(made.chat)}`,
      );
    };

    await page.reload();
    await open();

    for (const line of lines) {
      await expect(page.getByText(line.text, { exact: true })).toHaveCount(1, {
        timeout: 20_000,
      });
    }

    // What the migration writes for the first two: one page under the chat,
    // deterministic keys, `c` raised to keep the list's order.
    await page.evaluate(
      async ({ chat, entries }) => {
        const store = window.store;
        const log = await store.newResource({
          parent: chat,
          isA: 'https://atomicdata.dev/classes/ChatLog',
        });

        for (const e of entries) {
          log.putChatLogEntry(e.key, {
            a: store.getAgent()?.subject ?? '',
            t: '',
            c: e.createdAt,
            role: e.role,
            parts: JSON.stringify([{ type: 'text', text: e.text }]),
          });
        }

        await log.save();
        store.notifyResourceManuallyCreated(log);
      },
      {
        chat: made.chat,
        entries: made.messages.slice(0, 2).map((m, i) => ({
          key: migratedEntryKey(m.createdAt, m.subject),
          createdAt: m.createdAt,
          role: lines[i].role,
          text: lines[i].text,
        })),
      },
    );
    await waitForSynced(page);
    await page.reload();

    // Each text is on screen exactly once and in order: the first two are
    // entries, the stale resources behind them are hidden, the third has no
    // entry yet and is still listed.
    for (const line of lines) {
      await expect(page.getByText(line.text, { exact: true })).toHaveCount(1, {
        timeout: 20_000,
      });
    }

    const order = await page
      .getByText(new RegExp(`^old (question|answer|follow-up) ${stamp}$`))
      .allTextContents();
    expect(order).toEqual(lines.map(l => l.text));
  });

  test('a new chat writes its messages as entries of a page, not as resources', async ({
    page,
  }) => {
    test.slow();
    await sendChatMessage(page, 'Hello AI');
    await expect(page.getByText(MOCK_RESPONSE)).toBeVisible({
      timeout: 15_000,
    });
    await expect(
      page.getByTestId('sidebar').getByRole('link', { name: 'Test Chat' }),
    ).toBeVisible({ timeout: 15_000 });
    await waitForSynced(page);

    const href = await page
      .getByTestId('sidebar')
      .getByRole('link', { name: 'Test Chat' })
      .getAttribute('href');
    const chatSubject = isAtomicIdentifier(href!)
      ? href!
      : new URL(href!, page.url()).searchParams.get('subject')!;
    expect(chatSubject).toBeTruthy();

    const readStored = () =>
      page.evaluate(
        async ({ chat: subject, logClass, messageClass, messages }) => {
          const chat = await window.store.getResource(subject);
          const children = await chat.getChildrenCollection();
          await children.waitForReady();
          const found = { pages: [] as number[], messageResources: 0 };

          for (let i = 0; i < children.totalMembers; i++) {
            const member = await children.getMemberWithIndex(i);
            const child = member
              ? await window.store.getResource(member)
              : undefined;

            if (child?.hasClasses(logClass)) {
              found.pages.push(child.countChatLogEntries());
            }

            if (child?.hasClasses(messageClass)) found.messageResources++;
          }

          return { ...found, listed: chat.get(messages) };
        },
        {
          chat: chatSubject as string,
          logClass: 'https://atomicdata.dev/classes/ChatLog',
          messageClass: ai.classes.aiMessage,
          messages: ai.properties.messages,
        },
      );
    // One page with the question and the reply; nothing else is stored per message.
    await expect.poll(async () => (await readStored()).pages).toEqual([2]);
    const stored = await readStored();
    expect(stored.messageResources).toBe(0);
    expect(stored.listed ?? []).toEqual([]);

    // Reload: the question and the answer come back from the page's entries.
    await page.goto(
      `${new URL(page.url()).origin}/app/show?subject=${encodeURIComponent(chatSubject)}`,
    );
    await expect(page.getByText('Hello AI', { exact: true })).toBeVisible({
      timeout: 20_000,
    });
    await expect(page.getByText(MOCK_RESPONSE)).toBeVisible();
  });
});
