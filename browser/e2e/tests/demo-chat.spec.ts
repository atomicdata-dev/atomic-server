/**
 * The demo workspace's scripted speech is written as chat log entries
 * authored as the personas (planning/chat-log.md), not as Message resources.
 */
import { test, expect } from './fixtures';
import { FRONTEND_URL } from './test-utils';

test('the demo team chat shows its seeded lines as entries', async ({
  page,
}) => {
  test.setTimeout(180000);
  await page.goto(`${FRONTEND_URL}/app/demo`);
  await expect(page.getByText('This workspace is a demo')).toBeVisible({
    timeout: 90000,
  });
  await page.getByText('Team chat', { exact: true }).first().click();
  const entry = page.locator('[data-entry-key]').filter({
    hasText: 'the onboarding board is all set up',
  });
  await expect(entry).toBeVisible({ timeout: 30000 });
  await expect(page.locator('[data-entry-key]').first()).toBeVisible();
});

test('the demo opens in the onboarding meeting, greets the visitor, then moves to the board', async ({
  page,
}) => {
  test.setTimeout(180000);
  await page.goto(`${FRONTEND_URL}/app/demo`);

  // The first resource is the meeting, with its chat open beside it.
  await expect(
    page.getByRole('heading', { name: 'Onboarding meeting' }).first(),
  ).toBeVisible({ timeout: 90000 });
  const message = page.getByPlaceholder('type a message');
  await expect(message).toBeVisible({ timeout: 30000 });
  await expect(page.getByText('Issue Tracker').first()).toBeVisible();
  await expect(
    page.locator('[data-entry-key]').filter({ hasText: 'say hi' }),
  ).toBeVisible({ timeout: 60000 });

  // Still in the meeting: nothing moves them until they have said hi.
  const meetingUrl = page.url();

  await message.fill('Hi');
  await message.press('Enter');

  // Mara answers them directly, and promptly: she replies in about a second
  // alone and in 4 to 7 s with four workers on four cores, so the wait only
  // has to tell "answers" from "never answers" (the board move below is 60 s).
  await expect(
    page.locator('[data-entry-key]').filter({ hasText: 'Welcome to the team' }),
  ).toBeVisible({ timeout: 30000 });

  // Then they follow her to the board, where the card has been ticked.
  await expect(page).not.toHaveURL(meetingUrl, { timeout: 60000 });
  await expect(page.getByText('Say hi in the meeting chat')).toBeVisible();
});
