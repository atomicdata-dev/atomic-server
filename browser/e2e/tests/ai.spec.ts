import { test, expect, type Page } from './fixtures';
import { before, devDrive, newDrive, signIn } from './test-utils';
import {
  AFTER_COMPACT_USER,
  AFTER_UNCOMPACT_USER,
  enableAIForTesting,
  FIRST_RESPONSE,
  FIRST_USER,
  setupAICompactMocks,
  setupAIRouteMocks,
  setupAIToolCallMocks,
} from './ai-mock';

const MOCK_RESPONSE = 'This is a mock AI response.';

test.describe('AI Chat', () => {
  test.beforeEach(async ({ page }) => {
    // Route mocks and init scripts must be registered before page.goto()
    await setupAIRouteMocks(page, { chatResponse: MOCK_RESPONSE });
    await enableAIForTesting(page);
    await before({ page });
    await signIn(page);
    await newDrive(page);
  });

  test('sends a message and displays AI response', async ({ page }) => {
    await sendChatMessage(page, 'Hello AI');
    await expect(page.getByText(MOCK_RESPONSE)).toBeVisible({
      timeout: 15_000,
    });
  });

  test('saves the chat and shows it in the AI Chats panel', async ({
    page,
  }) => {
    await sendChatMessage(page, 'Hello AI');
    await expect(page.getByText(MOCK_RESPONSE)).toBeVisible({
      timeout: 15_000,
    });

    // AIPanel polls the search index after ResourceSaved until the new chat
    // shows up (see AIPanel.tsx's pollUntilIndexed), rather than waiting out
    // a fixed delay.
    await expect(
      page.getByTestId('sidebar').getByRole('link', { name: 'Test Chat' }),
    ).toBeVisible({ timeout: 15_000 });
  });

  test('new chat button clears the conversation', async ({ page }) => {
    await sendChatMessage(page, 'Hello AI');
    await expect(page.getByText(MOCK_RESPONSE)).toBeVisible({
      timeout: 15_000,
    });

    await page
      .getByTestId('ai-sidebar')
      .getByRole('button', { name: 'New Chat' })
      .click();
    await expect(page.getByText(MOCK_RESPONSE)).not.toBeVisible();
  });
});

test.describe('AI Tools', () => {
  // Shared across beforeEach and test body; safe because tests run serially.
  let toolState: Awaited<ReturnType<typeof setupAIToolCallMocks>>;

  test.beforeEach(async ({ page }) => {
    // setupAIToolCallMocks registers route intercepts including /models which
    // fires on page load — must be called before before() / page.goto().
    toolState = await setupAIToolCallMocks(page);
    await enableAIForTesting(page);
    await before({ page });
    await signIn(page);
  });

  test('tool calls create/edit/read a resource and show the review UI', async ({
    page,
  }) => {
    const { driveURL } = await newDrive(page);
    toolState.driveUrl = driveURL;

    await sendChatMessage(
      page,
      'Create a resource, edit it, then read it back',
    );

    // Each tool call renders a message bubble in the chat as it executes.
    // The create_resource title is parsed from the jsonAD name property.
    await expect(
      page.getByText('Creating AI Test Bookmark').first(),
    ).toBeVisible({ timeout: 15_000 });

    // edit_atomic_resource shows the property title and resource name.
    await expect(
      page.getByText(/Editing.*AI Test Bookmark/).first(),
    ).toBeVisible({ timeout: 10_000 });

    // get_atomic_resource shows "Reading <resource title>".
    await expect(
      page.getByText(/Reading.*AI Test Bookmark/).first(),
    ).toBeVisible({ timeout: 10_000 });

    // Wait for the full tool-call chain to complete and the final text to appear.
    await expect(
      page.getByText('Done! I created, edited, and read back the resource.'),
    ).toBeVisible({ timeout: 30_000 });

    // edit_atomic_resource calls onResourceEdited → reportAIEdit → floating button.
    const reviewButton = page.getByRole('button', { name: /Review \d+ edit/ });
    await expect(reviewButton).toBeVisible({ timeout: 10_000 });

    // Open the review dialog.
    await reviewButton.click();
    await expect(
      page.getByRole('heading', { name: 'Review Edits' }),
    ).toBeVisible();

    // Confirm the changes — saves the resource and dismisses the dialog.
    await page.getByTitle('Confirm Changes').click();
    await expect(
      page.getByRole('heading', { name: 'Review Edits' }),
    ).not.toBeVisible();
  });
});

test.describe('AI Compacting', () => {
  test.beforeEach(async ({ page }) => {
    await setupAICompactMocks(page);
    await enableAIForTesting(page);
    await page.addInitScript(() => {
      localStorage.setItem(
        'atomic.ai.showFollowUpPrompts',
        JSON.stringify(false),
      );
    });
    await before({ page });
    await signIn(page);
    await devDrive(page);
  });

  test('manual /compact trims context sent to the model', async ({ page }) => {
    test.setTimeout(180_000);

    const sendTimeout = 120_000;

    await sendChatMessage(page, FIRST_USER, { timeout: sendTimeout });
    await expect(page.getByText(FIRST_RESPONSE)).toBeVisible({
      timeout: 15_000,
    });

    await sendChatMessage(page, '/compact', { timeout: sendTimeout });
    await expect(page.getByText('Context compacted')).toBeVisible({
      timeout: 15_000,
    });

    await sendChatMessage(page, AFTER_COMPACT_USER, { timeout: sendTimeout });
    await expect(page.getByText('Compact context OK')).toBeVisible({
      timeout: 15_000,
    });

    const sidebar = page.locator('[data-open]');
    const summaryMessageRow = sidebar.locator('[data-summary-message]');
    await summaryMessageRow.hover();
    await summaryMessageRow.getByTitle('Delete Message').click();
    await expect(page.getByText('Context compacted')).not.toBeVisible({
      timeout: 15_000,
    });
    await expect(page.getByText(FIRST_USER)).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText(FIRST_RESPONSE)).toBeVisible({
      timeout: 15_000,
    });

    await sendChatMessage(page, AFTER_UNCOMPACT_USER, { timeout: sendTimeout });
    await expect(page.getByText('Uncompact context OK')).toBeVisible({
      timeout: 15_000,
    });
  });
});

/**
 * Types a message into the AI sidebar chat input and submits it by clicking
 * the Send button. Using the button (rather than Enter) is intentional: when a
 * new drive is created the server runs vector indexing, which disables the
 * Enter key handler for agents with canReadAtomicData. Waiting for the Send
 * button to be enabled also waits out that indexing delay.
 *
 * The sidebar is scoped via [data-open] to avoid matching other contenteditable
 * elements that may be present after drive creation. AIChatInput is lazily
 * loaded, so we wait explicitly for the contenteditable to appear.
 */
async function sendChatMessage(
  page: Page,
  text: string,
  options: { timeout?: number } = {},
) {
  const timeout = options.timeout ?? 30_000;
  const sidebar = page.locator('[data-open]');
  const chatInput = sidebar.locator('[contenteditable="true"]');

  // AIChatInput is the second lazy-loaded component inside the sidebar;
  // the "Atomic Assistant" heading appears before it, so we wait explicitly.
  await expect(chatInput).toBeVisible({ timeout: 15_000 });

  // Vector indexing after drive creation or chat save disables Send.
  const indexing = sidebar.getByText('Indexing', { exact: true });
  await indexing.waitFor({ state: 'hidden', timeout }).catch(() => {});

  await chatInput.click();
  await page.keyboard.type(text);

  // Wait for Send to be enabled — this naturally waits out server indexing.
  const sendButton = sidebar.getByTitle('Send');
  await expect(sendButton).toBeEnabled({ timeout });

  // Then wait for any toast to clear. Toasts stack in the bottom-right corner,
  // which is exactly where this sidebar's Send button is: the container is
  // `pointer-events: none` but each toast bar sets `auto` (it has Clear and
  // Copy buttons), so a leftover setup toast — "Signed in!", "Dev agent
  // created" — swallows the click for as long as it is on screen. Observed as
  // a 10s retry loop reporting `<div data-rht-toaster> subtree intercepts
  // pointer events`.
  //
  // Waiting rather than `{ force: true }` on purpose. Forcing would dispatch
  // the click regardless of what is on top, so this same helper would keep
  // passing if a dialog or an overlay ever genuinely covered Send — which is a
  // real bug and one this suite should be able to catch.
  // Hover pauses toast expiry; move away from the corner before waiting.
  await page.mouse.move(0, 0);
  await expect(page.locator('[data-rht-toaster] > div')).toHaveCount(0, {
    timeout: 15_000,
  });

  await sendButton.click();
}
