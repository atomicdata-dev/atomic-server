import { test, expect, type Page } from './fixtures';
import {
  before,
  createTableFromDialog,
  inDialog,
  pickTotal,
  waitForGridMounted,
} from './test-utils';

/** Creates an Issue Tracker table (Board + All issues views, no timestamps). */
async function createIssueTracker(page: Page, name: string) {
  await createTableFromDialog(page, { template: /Issue Tracker/, name });
  await expect(page.getByTestId('kanban-board')).toBeVisible();
}

/** Creates a Time tracker table and waits for the timer it opens on. */
async function createTimeTracker(page: Page, name: string) {
  await createTableFromDialog(page, { template: /Time tracker/, name });
  await expect(page.getByTestId('timer-new-input')).toBeVisible();
}

/** Adds a Timer view and waits for its toolbar (the view's marker). */
async function addTimerView(page: Page) {
  await page.getByRole('button', { name: 'Add view' }).click();
  await page.getByTestId('menu-item-timer').click();
  await expect(page.getByTestId('timer-new-input')).toBeVisible();
}

/** The grid row containing `text`. */
const row = (page: Page, text: string) =>
  page.getByRole('row').filter({ hasText: text });

test.describe('timer view', () => {
  test.beforeEach(before);

  test('start an entry, stop it, and it persists', async ({ page }) => {
    await createIssueTracker(page, 'Time tracking');
    await addTimerView(page);

    // Starting a named entry creates a row that is immediately running.
    await page.getByTestId('timer-new-input').fill('Write the report');
    await page.getByTestId('timer-start-new').click();

    const entry = row(page, 'Write the report');
    await expect(entry).toBeVisible();
    await expect(entry.getByTestId('timer-cell-action')).toHaveAttribute(
      'data-running',
      'true',
    );

    // The clock ticks: after a second the duration has moved off 0:00:00.
    await expect(entry.getByTestId('derived-duration')).not.toHaveText(
      '0:00:00',
      {
        timeout: 5000,
      },
    );

    // Stopping stamps the end — it offers "start again" instead of a stop.
    await entry.getByTestId('timer-stop').click();
    await expect(entry.getByTestId('timer-cell-action')).toHaveAttribute(
      'data-running',
      'false',
    );
    await expect(entry.getByTestId('timer-resume')).toBeVisible();

    // "Start again" COPIES the entry — it must not restart the original, which
    // would overwrite its start and clear its end, destroying the logged time.
    const stoppedDuration = await entry
      .getByTestId('derived-duration')
      .textContent();
    await entry.getByTestId('timer-resume').click();
    await expect(
      page.getByRole('row').filter({ hasText: 'Write the report' }),
    ).toHaveCount(2);
    // The original keeps its duration and stays stopped. (`entry` now matches
    // both rows, so address the first explicitly.)
    const original = page
      .getByRole('row')
      .filter({ hasText: 'Write the report' })
      .first();
    await expect(original.getByTestId('derived-duration')).toHaveText(
      stoppedDuration ?? '',
    );
    await expect(original.getByTestId('timer-cell-action')).toHaveAttribute(
      'data-running',
      'false',
    );
    // The copy is the one running; stop it again so the count below is stable.
    const copy = page
      .getByRole('row')
      .filter({ hasText: 'Write the report' })
      .last();
    await expect(copy.getByTestId('timer-cell-action')).toHaveAttribute(
      'data-running',
      'true',
    );
    await copy.getByTestId('timer-stop').click();

    // "One at a time" is on by default: starting a second entry stops the first.
    await page.getByTestId('timer-new-input').fill('Review the PR');
    await page.getByTestId('timer-start-new').click();

    const second = row(page, 'Review the PR');
    await expect(second.getByTestId('timer-cell-action')).toHaveAttribute(
      'data-running',
      'true',
    );
    await second.getByTestId('timer-stop').click();

    // Persisted: the active view is in the URL, so a reload comes back here.
    await page.reload();
    await expect(page.getByTestId('timer-new-input')).toBeVisible();
    // Two "Write the report" rows: the original and the "start again" copy.
    await expect(row(page, 'Write the report')).toHaveCount(2);
    await expect(row(page, 'Review the PR')).toHaveCount(1);
  });

  test('it is a real table: editing and column tools all work', async ({
    page,
  }) => {
    await createIssueTracker(page, 'Real table');
    await addTimerView(page);

    await page.getByTestId('timer-new-input').fill('Has columns');
    await page.getByTestId('timer-start-new').click();
    await expect(row(page, 'Has columns')).toBeVisible();

    // The timer renders the actual grid, so every table affordance is present:
    // real gridcells, headings with their column menu, add-column.
    await expect(page.getByRole('grid')).toBeVisible();
    await expect(
      page.getByRole('gridcell', { name: 'Has columns' }),
    ).toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Edit column' }).first(),
    ).toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Add column' }),
    ).toBeVisible();

    // A column created from this view shows up in it.
    await page.getByRole('button', { name: 'Add column' }).click();
    await page.click('text=Text');
    await inDialog(page, async (dialog, closeDialogWith) => {
      await dialog.getByPlaceholder('New Column').fill('Notes');
      await closeDialogWith('Create');
    });
    // Attached rather than in-viewport: a timer view leads with its Duration and
    // Start/Stop columns, so a newly added column sits past the right edge.
    await expect(
      page.getByRole('button', { name: 'Notes', exact: true }),
    ).toBeAttached();
  });

  test('concurrent timers once "one at a time" is off', async ({ page }) => {
    await createIssueTracker(page, 'Parallel work');
    await addTimerView(page);

    await page.getByTestId('timer-exclusive').uncheck();

    await page.getByTestId('timer-new-input').fill('Backend');
    await page.getByTestId('timer-start-new').click();
    await expect(row(page, 'Backend')).toBeVisible();

    await page.getByTestId('timer-new-input').fill('Frontend');
    await page.getByTestId('timer-start-new').click();
    await expect(row(page, 'Frontend')).toBeVisible();

    // Both keep running.
    await expect(
      row(page, 'Backend').getByTestId('timer-cell-action'),
    ).toHaveAttribute('data-running', 'true');
    await expect(
      row(page, 'Frontend').getByTestId('timer-cell-action'),
    ).toHaveAttribute('data-running', 'true');

    // The setting lives on the View, so it survives a reload.
    await page.reload();
    await expect(page.getByTestId('timer-exclusive')).not.toBeChecked();
  });

  test('the active view is in the URL', async ({ page }) => {
    await createIssueTracker(page, 'Addressable');
    await addTimerView(page);

    await page.getByRole('tab', { name: 'All issues' }).click();
    await expect(page).toHaveURL(/[?&]view=/);
    const tableUrl = page.url();

    await page.getByRole('tab', { name: 'Timer' }).click();
    await expect(page.getByTestId('timer-new-input')).toBeVisible();

    // Back returns to the previous view rather than leaving the table, and the
    // URL alone is enough to land on it.
    await page.goBack();
    await expect(page.getByTestId('timer-new-input')).toHaveCount(0);

    await page.goto(tableUrl);
    await expect(page.getByTestId('timer-new-input')).toHaveCount(0);
  });

  test('the Time tracker template lands on a working timer', async ({
    page,
  }) => {
    // The template is the whole setup: no adding a view, no auto-created
    // Start/End, no column toggling. It opens straight into the timer.
    await createTimeTracker(page, 'My hours');

    // Its Project column is already present.
    // Attached, not in-viewport: the timer's own columns come first, pushing the
    // data columns to the right of the fold.
    await expect(
      page.getByRole('button', { name: 'Project', exact: true }),
    ).toBeAttached();
    // Wait for the grid itself, so the collection is loaded before adding.
    await expect(page.getByRole('grid')).toBeVisible();
    await waitForGridMounted(page);

    // Starting an entry works immediately on a freshly-created table — no
    // reload needed (regression: the new row was persisted but not rendered).
    await page.getByTestId('timer-new-input').fill('Invoicing');
    await page.getByTestId('timer-start-new').click();

    const entry = row(page, 'Invoicing');
    await expect(entry).toBeVisible();
    await expect(entry.getByTestId('timer-cell-action')).toHaveAttribute(
      'data-running',
      'true',
    );
  });

  test('the duration is view config, so a plain table renders it too', async ({
    page,
  }) => {
    await createTimeTracker(page, 'Config not code');
    await expect(page.getByRole('grid')).toBeVisible();
    await waitForGridMounted(page);

    await page.getByTestId('timer-new-input').fill('Configured work');
    await page.getByTestId('timer-start-new').click();
    const entry = row(page, 'Configured work');
    await expect(entry).toBeVisible();
    await entry.getByTestId('timer-stop').click();
    await expect(entry.getByTestId('timer-resume')).toBeVisible();
    const stopped = await entry.getByTestId('derived-duration').textContent();

    // Duration is stored on the View by the template, not built into the timer:
    // turning this view into a plain table keeps the column, while the
    // genuinely timer-specific Start/Stop column goes away.
    await page.getByRole('tab', { name: 'Timer' }).click();
    await page.getByTestId('menu-item-kind-table').click();
    await expect(page.getByTestId('timer-new-input')).toHaveCount(0);

    await expect(
      row(page, 'Configured work').getByTestId('derived-duration'),
    ).toHaveText(stopped ?? '');
    await expect(page.getByTestId('timer-cell-action')).toHaveCount(0);
  });

  test('the properties the view is built on cannot be toggled off', async ({
    page,
  }) => {
    await createIssueTracker(page, 'Locked props');
    await addTimerView(page);

    await page.getByRole('button', { name: 'Toggle properties' }).click();
    await expect(page.getByRole('menuitem', { name: 'Start' })).toBeDisabled();
    await expect(page.getByRole('menuitem', { name: 'End' })).toBeDisabled();
    await expect(page.getByRole('menuitem', { name: 'Status' })).toBeEnabled();
  });
  test('a duration can be totalled, and broken down per day', async ({
    page,
  }) => {
    test.slow();
    // Wide enough that the footer cell under Duration can be clicked.
    await page.setViewportSize({ width: 1800, height: 900 });

    await createTimeTracker(page, 'Totalled hours');
    await expect(page.getByRole('grid')).toBeVisible();
    await waitForGridMounted(page);

    // Two logged entries, both stopped, so their durations are settled.
    for (const name of ['Invoicing', 'Standup']) {
      await page.getByTestId('timer-new-input').fill(name);
      await page.getByTestId('timer-start-new').click();
      await expect(row(page, name)).toBeVisible();
      await row(page, name).getByTestId('timer-stop').click();
      await expect(row(page, name).getByTestId('timer-resume')).toBeVisible();
    }

    // Duration leads a timer view, so its footer cell is the first after the
    // row-count one. A duration is COMPUTED, not stored — totalling one is what
    // this covers.
    const footer = page.getByTestId('table-totals');
    await pickTotal(page, footer.locator('[aria-colindex="2"]'), 'sum');

    // Formatted as a clock, like the column itself: milliseconds would be
    // unreadable. Both entries were sub-minute, so the total is 0:00:0x.
    await expect(footer).toContainText('Sum', { timeout: 15_000 });
    await expect(footer).toHaveText(/0:00:\d{2}/, { timeout: 15_000 });

    // The day totals the plan called out as blocked: break the same sum down by
    // the day each entry started.
    await expect(page.locator('[role="menu"]')).toHaveCount(0);
    await footer.locator('[aria-colindex="1"]').click();
    await page.getByTestId('menu-item-breakdown').click();
    await inDialog(page, async () => {
      await page
        .getByTestId('breakdown-column')
        .selectOption({ label: 'Start' });
      await page.getByTestId('breakdown-save').click();
    });

    const breakdown = page.getByTestId('table-breakdown');
    await expect(breakdown).toBeVisible({ timeout: 15_000 });
    // Both entries started today: one bucket, holding both.
    await expect(breakdown).toContainText('2 rows');
    await expect(breakdown).toHaveText(/0:00:\d{2}/);

    // It is configuration on the View, so it survives a reload.
    await page.reload();
    await expect(page.getByRole('grid')).toBeVisible();
    await expect(page.getByTestId('table-totals')).toContainText('Sum', {
      timeout: 15_000,
    });
  });
});
