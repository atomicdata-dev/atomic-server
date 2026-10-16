import { before } from './session-fixtures';
import { test, expect, type Page } from './session-fixtures';
import { createTableFromDialog } from './test-utils';

/**
 * The Issue Tracker template's issue list: an Open / Closed split over the
 * same Status column the board groups by. Walks one issue through its life —
 * opened, closed, found under Closed, reopened.
 */

/** The issue list's row for `title`. */
const issue = (page: Page, title: string) =>
  page.getByTestId('issue-row').filter({ hasText: title });

test.describe('issues view', () => {
  test.beforeEach(before);

  test('an issue can be opened, closed and reopened', async ({ page }) => {
    // Named "Bugs", which the new-table dialog singularizes to "Bug".
    await createTableFromDialog(page, {
      template: /Issue Tracker/,
      name: 'Bugs',
    });
    await expect(page.getByTestId('kanban-board')).toBeVisible();

    // The template no longer ships an Issues tab; add the view like any other.
    await page.getByRole('button', { name: 'Add view' }).click();
    await page.getByTestId('menu-item-issues').click();
    const view = page.getByTestId('issues-view');
    await expect(view).toBeVisible();

    const openFilter = view.getByRole('button', { name: /Open$/ });
    const closedFilter = view.getByRole('button', { name: /Closed$/ });
    await expect(openFilter).toHaveAttribute('aria-pressed', 'true');

    const title = 'Login button does nothing';
    await view.getByRole('button', { name: 'New bug' }).click();
    const input = view.getByRole('textbox', { name: 'New bug title' });
    await input.fill(title);
    await input.press('Enter');

    await expect(issue(page, title)).toBeVisible();
    await expect(openFilter).toContainText('1 Open');

    // Close it: it leaves the Open list and shows up under Closed.
    await issue(page, title).hover();
    await issue(page, title)
      .getByRole('button', { name: `Close ${title}` })
      .click();
    await expect(issue(page, title)).toHaveCount(0);
    await expect(closedFilter).toContainText('1 Closed');

    await closedFilter.click();
    await expect(closedFilter).toHaveAttribute('aria-pressed', 'true');
    await expect(issue(page, title)).toBeVisible();
    await expect(
      issue(page, title).getByRole('img', { name: 'Closed' }),
    ).toBeVisible();

    // Reopen it: back under Open.
    await issue(page, title).hover();
    await issue(page, title)
      .getByRole('button', { name: `Reopen ${title}` })
      .click();
    await expect(issue(page, title)).toHaveCount(0);

    await openFilter.click();
    await expect(issue(page, title)).toBeVisible();
    await expect(
      issue(page, title).getByRole('img', { name: 'Open' }),
    ).toBeVisible();
  });
});
