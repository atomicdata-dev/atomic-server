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
  // This test fails in CI only, so keep the page's console to print when it
  // does: what the app logged around the visitor's message is the evidence.
  const consoleLines: string[] = [];
  page.on('console', msg =>
    consoleLines.push(`[${msg.type()}] ${msg.text().slice(0, 500)}`),
  );
  page.on('pageerror', err => consoleLines.push(`[pageerror] ${err.message}`));
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
  await expect(message).toHaveValue('Hi');
  await message.press('Enter');

  try {
    // Their own message lands first: without it there is nothing to answer.
    await expect(
      page
        .locator('[data-entry-key]')
        .filter({ has: page.getByText('Hi', { exact: true }) }),
    ).toBeVisible({ timeout: 15000 });

    // Mara answers them directly, and promptly.
    await expect(
      page
        .locator('[data-entry-key]')
        .filter({ hasText: 'Welcome to the team' }),
    ).toBeVisible({ timeout: 5000 });
  } catch (e) {
    console.log(
      `demo-chat: browser console up to the failure:\n${consoleLines.slice(-80).join('\n')}`,
    );
    throw e;
  }

  // Then they follow her to the board, where the card has been ticked.
  await expect(page).not.toHaveURL(meetingUrl, { timeout: 60000 });
  await expect(page.getByText('Say hi in the meeting chat')).toBeVisible();
});
