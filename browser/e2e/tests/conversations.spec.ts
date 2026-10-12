/**
 * Encrypted conversations: one person starts a DM with another by their
 * Atomic ID, and both read and answer it. The other person finds it without
 * being told, through the server's `/conversations`. That the server only
 * ever holds ciphertext is covered in `atomic_lib::conversation`.
 */
import { test, expect, type Page } from './fixtures';
import {
  before,
  devDrive,
  installCommitWatcher,
  SERVER_URL,
  timestamp,
} from './test-utils';

const chatInput = (page: Page) => page.getByLabel('Chat input');

async function agentSubject(page: Page): Promise<string> {
  await page.waitForFunction(() => !!window.store?.getAgent()?.subject);

  return page.evaluate(() => window.store.getAgent()!.subject!);
}

/** Waits until `agent` has published its encryption key, so it can be
 *  messaged. The app does that shortly after start. */
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
  await chatInput(page).fill(text);
  await page.getByRole('button', { name: 'Send' }).click();
  await expect(page.getByText(text)).toBeVisible({ timeout: 15_000 });
}

test.describe('conversations', () => {
  test.beforeEach(before);

  test('two people message each other, encrypted', async ({
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

    // Alice starts the conversation from the Messages panel.
    await page.getByTestId('new-message').click();
    await page.getByLabel('Who').fill(bobSubject);
    await page.getByRole('button', { name: 'Start conversation' }).click();
    await expect(page.getByText('End-to-end encrypted')).toBeVisible({
      timeout: 30_000,
    });
    const hello = `Hello Bob ${timestamp()}`;
    await send(page, hello);

    // Bob finds it in his Messages panel without a link, and reads it.
    await bob.reload();
    const item = bob.getByTestId('conversation-item').first();
    await expect(item).toBeVisible({ timeout: 30_000 });
    await item.click();
    await expect(bob.getByText(hello)).toBeVisible({ timeout: 30_000 });

    // And his answer reaches Alice while she has the conversation open.
    const reply = `Hi Alice ${timestamp()}`;
    await send(bob, reply);
    await expect(page.getByText(reply)).toBeVisible({ timeout: 30_000 });

    await bobContext.close();
  });
});
