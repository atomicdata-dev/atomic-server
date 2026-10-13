import { before } from './session-fixtures';
import { test, expect, type Page } from './session-fixtures';
import {
  createTableFromDialog,
  setGridCell,
  waitForGridMounted,
  waitForRowsMaterialized,
  waitForSynced,
} from './test-utils';

/**
 * Commenting on a table row, Notion-style.
 *
 * A row is a resource of its own, so its thread is the ordinary comment
 * thread: Messages whose `about` points at the row. What is new is reaching
 * it — a bubble in the row's gutter, and a comments panel that can be aimed at
 * something inside the page rather than at the page's own resource.
 *
 * Covers:
 *   1. The gutter bubble opens the panel for that row, headed by the row's
 *      title, and a comment posted there sticks to the row (a live count on
 *      the bubble, surviving a reload).
 *   2. Each row keeps its own thread: clicking another row's bubble switches
 *      threads rather than closing the panel.
 *   3. The trailing entry row has no resource yet, so it offers no bubble.
 */

const ROWS = ['Alpha', 'Beta'] as const;

/** The gutter bubble of the grid row at `aria-rowindex` (1 is the header). */
const bubble = (page: Page, rowIndex: number) =>
  page
    .locator(`[aria-rowindex="${rowIndex}"]`)
    .getByTestId('row-comment-button');

/**
 * Clicks a row's bubble the way a user reaches it. A row with no comments
 * keeps its bubble out of the way until the pointer is somewhere in the row,
 * so the hover is part of the gesture, not test scaffolding.
 */
async function openRowComments(page: Page, rowIndex: number) {
  // Hover the row's first data cell, not the row itself: the row box is as wide
  // as all its columns, so hovering its centre would scroll the grid sideways
  // and take the gutter with it.
  await page
    .locator(`[aria-rowindex="${rowIndex}"] > [aria-colindex="2"]`)
    .hover();
  await bubble(page, rowIndex).click();
}

test.describe('table row comments', () => {
  test.beforeEach(before);

  test('each row carries its own thread, reachable from the gutter', async ({
    page,
  }) => {
    test.slow();

    await createTableFromDialog(page, { name: 'Commented' });
    await waitForGridMounted(page);

    // Two saved rows. Typing into the trailing entry row materializes it and
    // spawns a fresh placeholder below, so after both the grid holds rows 2
    // and 3 plus an empty row 4.
    for (const [index, name] of ROWS.entries()) {
      await setGridCell(page, index + 2, 2, name);
    }

    await waitForRowsMaterialized(page);

    // The entry row is local until it is typed into — nothing for a comment to
    // point at, so no bubble.
    await expect(bubble(page, 2)).toHaveCount(1);
    await expect(bubble(page, ROWS.length + 2)).toHaveCount(0);

    // Comment on the first row.
    await openRowComments(page, 2);
    const panel = page.getByTestId('comments-panel');
    await expect(panel).toHaveAttribute('data-open', '');
    // The page still shows the whole table, so the panel says which row it is.
    await expect(panel.getByTestId('comments-panel-subtitle')).toHaveText(
      ROWS[0],
      { timeout: 15000 },
    );

    const chatInput = panel.getByLabel('Chat input');
    await expect(chatInput).toBeVisible({ timeout: 15000 });
    await chatInput.fill('Needs a second look');
    await chatInput.press('Enter');
    await expect(chatInput).toHaveValue('');
    await expect(panel.locator('text=Needs a second look').first()).toBeVisible(
      { timeout: 15000 },
    );

    // The comment is an entry in the row's chat log page, not a resource.
    await expect(
      panel
        .locator('[data-entry-key]')
        .filter({ hasText: 'Needs a second look' }),
    ).toHaveCount(1);

    // The count is live, and it belongs to the first row alone.
    await expect(bubble(page, 2)).toHaveText('1', { timeout: 15000 });
    await expect(bubble(page, 3)).toHaveText('');

    // Another row's bubble switches threads rather than closing the panel.
    await openRowComments(page, 3);
    await expect(panel).toHaveAttribute('data-open', '');
    await expect(panel.getByTestId('comments-panel-subtitle')).toHaveText(
      ROWS[1],
      { timeout: 15000 },
    );
    await expect(panel.locator('text=Needs a second look')).toHaveCount(0);

    // Clicking the row whose thread is up closes the panel.
    await openRowComments(page, 3);
    await expect(panel).not.toHaveAttribute('data-open', '');

    // The comment is on the row, not on this tab: it is still there, and still
    // counted, after a reload — once the commit has reached the server.
    await waitForSynced(page);
    await page.reload();
    await waitForGridMounted(page);
    await expect(bubble(page, 2)).toHaveText('1', { timeout: 30000 });

    await openRowComments(page, 2);
    await expect(
      page.getByTestId('comments-panel').locator('text=Needs a second look'),
    ).toBeVisible({ timeout: 15000 });

    // A second comment goes to the same page: the count adds up, and the
    // unread badge clears while the thread is open.
    const input = page.getByTestId('comments-panel').getByLabel('Chat input');
    await input.fill('And a follow-up');
    await input.press('Enter');
    await expect(
      page.getByTestId('comments-panel').locator('[data-entry-key]'),
    ).toHaveCount(2, { timeout: 15000 });
    await expect(bubble(page, 2)).toHaveText('2', { timeout: 15000 });
  });
});
