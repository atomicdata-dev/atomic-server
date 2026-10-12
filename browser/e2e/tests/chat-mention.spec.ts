/**
 * @-mentions in the chat composer: typing `@` searches the drive like the
 * document editor does, and the picked resource is stored in the message in
 * the format `Markdown` already renders, as a link to the resource.
 */
import { test, expect } from './fixtures';
import { before, getCurrentSubject, newResource } from './test-utils';

test.describe('chat mentions', () => {
  test.beforeEach(before);

  test('@ in a chat room mentions a resource', async ({ page }) => {
    test.slow();

    await newResource('folder', page);
    await page.keyboard.type('Mention Target');
    await page.keyboard.press('Enter');
    await expect(
      page.getByRole('heading', { name: 'Mention Target' }),
    ).toBeVisible({ timeout: 10000 });
    const targetSubject = await getCurrentSubject(page);

    await newResource('chatroom', page);
    const input = page.getByLabel('Chat input');
    await expect(input).toBeVisible({ timeout: 15000 });

    await input.pressSequentially('see @Mention');
    const picker = page.getByTestId('chat-mention-picker');
    await expect(picker).toBeVisible();
    await picker
      .getByRole('button', { name: 'Mention Target' })
      .click({ timeout: 15000 });

    await expect(input).toHaveValue(
      `see [@ id="${targetSubject}" label="Mention Target"] `,
    );
    await input.press('Enter');

    await expect(
      page.getByRole('main').getByText('Mention Target'),
    ).toBeVisible({ timeout: 10000 });
    // The mention is stored in a chat log entry and rendered from it.
    await expect(
      page.locator('[data-entry-key]').filter({ hasText: 'Mention Target' }),
    ).toHaveCount(1);

    // Drive members are found by name too (the dev user is the drive owner).
    await input.pressSequentially('and @Dev');
    await expect(
      page.getByTestId('chat-mention-picker').getByRole('button', {
        name: 'Dev User',
      }),
    ).toBeVisible({ timeout: 15000 });
  });
});
