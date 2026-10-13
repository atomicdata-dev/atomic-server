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

  // Chat bubbles (toasts) seen from the start: the demo must not announce its
  // seeded team chat as new messages while it is being built or before the
  // scenario has begun.
  await page.addInitScript(() => {
    const seen: string[] = [];
    (window as unknown as { __bubbles: string[] }).__bubbles = seen;
    setInterval(() => {
      document
        .querySelectorAll('div[style*="z-index: 9999"] button')
        .forEach(el => seen.push((el as HTMLElement).innerText));
    }, 100);
  });
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

  // Nothing popped up on the way in, and the chat is showing its newest line.
  expect(
    await page.evaluate(
      () => (window as unknown as { __bubbles: string[] }).__bubbles,
    ),
  ).toEqual([]);
  await expect
    .poll(() =>
      page.evaluate(() => {
        const list = [
          ...document.querySelectorAll('[data-radix-scroll-area-viewport]'),
        ].find(el => el.querySelector('[data-entry-key]'));

        return list
          ? list.scrollHeight - list.scrollTop - list.clientHeight
          : -1;
      }),
    )
    .toBeLessThan(8);

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
