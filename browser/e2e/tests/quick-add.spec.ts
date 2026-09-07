import { test, expect, type Page } from './fixtures';
import {
  before,
  createTableFromDialog,
  inDialog,
  reloadGrid,
  waitForGridMounted,
} from './test-utils';

/**
 * A quick-add is the button a personal app is mostly used through: name a thing
 * and it exists, or press once and the moment is recorded. It is view
 * configuration, so what is worth proving is that a configured button arrives
 * working, that pressing it commits a row, and that a person can add one.
 */

/** The grid row containing `text`. */
const row = (page: Page, text: string) =>
  page.getByRole('row').filter({ hasText: text });

async function createFromTemplate(
  page: Page,
  template: RegExp,
  name: string,
  openView?: string,
) {
  await createTableFromDialog(page, { template, name });

  if (openView) {
    await page.getByRole('tab', { name: openView }).click();
  }

  await expect(page.getByRole('grid')).toBeVisible();
  await waitForGridMounted(page);
}

/**
 * The dates a "stamped today" cell could legitimately be showing.
 *
 * Two things make a single `toLocaleDateString()` the wrong expectation. The
 * stamp lands at some instant after this is read, so a run crossing midnight
 * would compare against a day that arrived later. And the stamp is derived in
 * UTC while this reads local time — in a UTC+2 timezone just after local
 * midnight the app writes YESTERDAY's date, which is worth a look on its own
 * but is not what this test is about.
 */
async function plausibleStampDates(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const now = new Date();
    const utc = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()),
    );

    return [
      now.toLocaleDateString('en-GB'),
      utc.toLocaleDateString('en-GB', { timeZone: 'UTC' }),
    ];
  });
}

/** Matches any date the stamp could carry, read across the stamping action. */
async function stampedSince(page: Page, earlier: string[]): Promise<RegExp> {
  const esc = (d: string) => d.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const all = [...new Set([...earlier, ...(await plausibleStampDates(page))])];

  return new RegExp(all.map(esc).join('|'));
}

test.describe('quick add', () => {
  test.beforeEach(before);
  test.slow();

  test('the Grocery list names a thing and it exists', async ({ page }) => {
    await page.setViewportSize({ width: 1800, height: 900 });
    await createFromTemplate(page, /Grocery list/, 'Shopping', 'List');

    const input = page.getByTestId('quick-add-input');
    const button = page.getByTestId('quick-add-button');

    await expect(input).toHaveAttribute('placeholder', 'What do you need?');
    // Nothing typed, so there is nothing to create — a blank row would be a
    // worse guess than doing nothing.
    await expect(button).toBeDisabled();

    await input.fill('Milk');
    await expect(button).toBeEnabled();
    await button.click();

    await expect(row(page, 'Milk')).toBeVisible({ timeout: 15_000 });
    // The field clears, so the next item is one keystroke away.
    await expect(input).toHaveValue('');

    // Enter is the same as pressing it — this is a bar you use at speed.
    await input.fill('Bread');
    await input.press('Enter');
    await expect(row(page, 'Bread')).toBeVisible({ timeout: 15_000 });

    await reloadGrid(page);
    await expect(row(page, 'Milk')).toBeVisible();
    await expect(row(page, 'Bread')).toBeVisible();
  });

  /**
   * Naming a second item while the first is still saving.
   *
   * This is the normal way the bar gets used — it exists to be typed into at
   * speed — and it used to drop the keystroke silently: no row, no error, the
   * text still sitting in the field. On a fast machine the save lands between
   * the two, so the gap only opened under load, which is where it was found.
   *
   * Held open deliberately here rather than hoped for: the commit POST is
   * delayed so the second item is always typed mid-save.
   */
  test('a second item typed while the first is still saving is not lost', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1800, height: 900 });
    await createFromTemplate(page, /Grocery list/, 'Shopping', 'List');

    // Commits travel over the websocket while connected, so delaying the HTTP
    // /commit route holds nothing — an earlier version of this test did that
    // and passed against the bug it was written for.
    let holdCommits = true;
    // Scoped to the server's own socket (`/ws`, see `websockets.ts`) rather
    // than every socket the page opens.
    await page.routeWebSocket('**/ws', ws => {
      const server = ws.connectToServer();
      ws.onMessage(async message => {
        if (holdCommits) {
          await new Promise(resolve => setTimeout(resolve, 2500));
        }

        server.send(message);
      });
      server.onMessage(message => ws.send(message));
    });

    const input = page.getByTestId('quick-add-input');

    await input.fill('Milk');
    await page.getByTestId('quick-add-button').click();

    // No wait for Milk's row: the point is to type while its save is in
    // flight. The field clearing is the signal that the create was accepted.
    await expect(input).toHaveValue('');

    await input.fill('Bread');
    await input.press('Enter');
    // If the keystroke was swallowed, the text stays put — assert on that
    // directly, so a failure names the actual symptom.
    await expect(input).toHaveValue('');

    holdCommits = false;

    await expect(row(page, 'Milk')).toBeVisible({ timeout: 20_000 });
    await expect(row(page, 'Bread')).toBeVisible({ timeout: 20_000 });

    await reloadGrid(page);
    await expect(row(page, 'Milk')).toBeVisible();
    await expect(row(page, 'Bread')).toBeVisible();
  });

  test('the Workout log records the moment with no field at all', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1800, height: 900 });
    await createFromTemplate(page, /Workout log/, 'Training');

    // No field: the button is the whole interaction.
    await expect(page.getByTestId('quick-add-input')).toHaveCount(0);

    const button = page.getByTestId('quick-add-button');
    await expect(button).toContainText('Log set');
    const dateBeforeStamp = await plausibleStampDates(page);
    await button.click();

    // The preset stamped today's date, so the row lands where it belongs
    // without anything being typed.
    await reloadGrid(page);
    await expect(page.getByRole('grid')).toContainText(
      await stampedSince(page, dateBeforeStamp),
      { timeout: 15_000 },
    );
  });

  test('a person can add a create button, and it persists', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1800, height: 900 });
    // Expenses ships none, so this proves the dialog rather than the template.
    await createFromTemplate(page, /Expenses/, 'Spending');

    await expect(page.getByTestId('quick-add-button')).toHaveCount(0);

    // Configured from the active view's tab menu — it is view config, so it
    // lives with the view.
    await page
      .getByRole('tab', { name: 'All expenses' })
      .click({ button: 'right' });
    await page.getByRole('menuitem', { name: /create button/ }).click();

    await inDialog(page, async () => {
      await page.getByTestId('quick-add-config-label').fill('Add expense');
      await page.getByTestId('quick-add-config-preset').selectOption('setNow');
      await page
        .getByTestId('quick-add-config-preset-property')
        .selectOption({ label: 'Date' });
      await page.getByTestId('quick-add-config-save').click();
    });

    const button = page.getByTestId('quick-add-button');
    await expect(button).toContainText('Add expense', { timeout: 15_000 });

    await page.getByTestId('quick-add-input').fill('Coffee');
    const dateBeforeStamp2 = await plausibleStampDates(page);
    await button.click();
    await expect(row(page, 'Coffee')).toBeVisible({ timeout: 15_000 });

    // It is stored on the View, so it survives a reload — and so does the
    // preset it wrote.
    await reloadGrid(page);
    await expect(page.getByTestId('quick-add-button')).toContainText(
      'Add expense',
    );
    await expect(row(page, 'Coffee')).toContainText(
      await stampedSince(page, dateBeforeStamp2),
    );
  });
});
