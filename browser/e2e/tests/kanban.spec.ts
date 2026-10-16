import { before } from './session-fixtures';
import { test, expect, type Page, type Locator } from './session-fixtures';
import { createTableFromDialog, reloadReconnected, smoke } from './test-utils';

const NAME_PROP = 'https://atomicdata.dev/properties/name';

/**
 * Wait until a resource named `title` lists `column`'s tag subject on some
 * array property (the group-by / Status field).
 *
 * Kanban drag keeps a visual preview until `set()` writes that tag. Reloading
 * off the preview is what made the persist test fail: OPFS still had Todo.
 * Compare against the column's `data-kanban-column-id` (the tag subject) —
 * looking up the tag resource's name is racy; it may not be in the store.
 */
async function waitForCardStatus(page: Page, title: string, col: Locator) {
  const tagSubject = await col
    .getByTestId('kanban-column-body')
    .getAttribute('data-kanban-column-id');

  if (!tagSubject) {
    throw new Error('kanban column body has no data-kanban-column-id');
  }

  await page.waitForFunction(
    ({ cardTitle, expectedTag, nameProp }) => {
      const store = window.store;

      if (!store) {
        return false;
      }

      for (const resource of store.resources.values()) {
        if (resource.get?.(nameProp) !== cardTitle) {
          continue;
        }

        for (const [, value] of resource.getEntries?.() ?? []) {
          const subjects = Array.isArray(value) ? value : [];

          if (subjects.includes(expectedTag)) {
            return true;
          }
        }
      }

      return false;
    },
    { cardTitle: title, expectedTag: tagSubject, nameProp: NAME_PROP },
    { timeout: 30_000 },
  );
}

/**
 * Drag `source` onto `target` in a way that satisfies @dnd-kit's MouseSensor,
 * which only starts a drag after the pointer moves past a 10px activation
 * distance. A plain Playwright `dragTo` moves in one hop and never trips that
 * threshold, so we drive the mouse manually: press, nudge >10px to activate,
 * travel to the target in steps (so `onDragOver` fires along the way), then
 * release.
 */
async function dndDrag(page: Page, source: Locator, target: Locator) {
  // Wait for the card to stop moving: after a previous drop the board runs a
  // FLIP animation, and a press aimed at where the card was lands on nothing.
  await source.hover();
  const s = await source.boundingBox();

  if (!s) {
    throw new Error('drag source has no bounding box');
  }

  const sx = s.x + s.width / 2;
  const sy = s.y + s.height / 2;

  await page.mouse.move(sx, sy);
  await page.mouse.down();
  // Exceed the 10px activation distance to start the drag.
  await page.mouse.move(sx + 15, sy, { steps: 5 });

  // Measure the target only now: activating a drag changes the board's
  // layout (the "No status" column mounts, the dragged card leaves the
  // flow), so a box read before the drag can point at empty space.
  const t = await target.boundingBox();

  if (!t) {
    throw new Error('drag target has no bounding box');
  }

  const tx = t.x + t.width / 2;
  const ty = t.y + t.height / 2;

  await page.mouse.move(tx, ty, { steps: 10 });
  // A tiny extra move ensures the final `onDragOver` lands on the target.
  await page.mouse.move(tx, ty + 1, { steps: 2 });
  await page.mouse.up();
}

/**
 * Like `dndDrag`, but for a `target` that only mounts once the drag is
 * already active (the "No status" column is hidden while empty and appears
 * for the duration of a drag) — its bounding box can't be read up front, so
 * it's resolved from `targetTestId` only after the drag has activated.
 */
async function dndDragToLateMountedTarget(
  page: Page,
  source: Locator,
  targetTestId: string,
) {
  const s = await source.boundingBox();

  if (!s) {
    throw new Error('drag source has no bounding box');
  }

  const sx = s.x + s.width / 2;
  const sy = s.y + s.height / 2;

  await page.mouse.move(sx, sy);
  await page.mouse.down();
  // Exceed the 10px activation distance to start the drag — only after this
  // does the late-mounted target exist in the DOM.
  await page.mouse.move(sx + 15, sy, { steps: 5 });

  const target = page.getByTestId(targetTestId).last();
  // Wait for the readiness signal (the target mounting post-activation),
  // not a fixed delay — it doesn't exist until the drag state above commits.
  await target.waitFor({ state: 'visible' });
  const t = await target.boundingBox();

  if (!t) {
    throw new Error('drag target has no bounding box');
  }

  const tx = t.x + t.width / 2;
  const ty = t.y + t.height / 2;

  await page.mouse.move(tx, ty, { steps: 10 });
  await page.mouse.move(tx, ty + 1, { steps: 2 });
  await page.mouse.up();
}

const column = (page: Page, name: string) =>
  page.getByTestId('kanban-column').filter({ hasText: name });

const cardIn = (col: Locator, title: string) =>
  col.getByTestId('kanban-card').filter({ hasText: title });

/** Creates an Issue Tracker table and lands on its kanban board. */
async function createIssueTracker(page: Page, name: string) {
  await createTableFromDialog(page, { template: /Issue Tracker/, name });
  await expect(page.getByTestId('kanban-board')).toBeVisible();
}

/**
 * Adds a card with `title` to the given column via its inline "Add …"
 * button. The label is the table's row name — `createIssueTracker` always
 * names the table "Bugs", which `NewTableDialog` auto-singularizes to "Bug".
 */
async function addCard(page: Page, col: Locator, title: string) {
  await col.getByRole('button', { name: 'Add Bug' }).first().click();
  const input = col.getByPlaceholder('Bug title…');
  await input.fill(title);
  await input.press('Enter');
  // Close the (rapid-entry) input so it doesn't overlap later interactions.
  await input.press('Escape');
  await expect(cardIn(col, title)).toBeVisible();
}

test.describe('kanban', () => {
  test.beforeEach(before);

  test('issue-tracker template opens a kanban board with status columns', async ({
    page,
  }) => {
    await createIssueTracker(page, 'Bugs');

    // Both views exist (rendered as tabs); the kanban board is the default.
    await expect(page.getByRole('tab', { name: 'Board' })).toBeVisible();
    await expect(page.getByRole('tab', { name: 'All issues' })).toBeVisible();

    for (const status of ['todo', 'doing', 'done']) {
      await expect(column(page, status)).toBeVisible();
    }

    // A freshly created board has no uncategorized issues yet — the "No
    // status" column stays hidden until one exists.
    await expect(column(page, 'No status')).not.toBeVisible();
  });

  test('the "No status" column appears once an issue has no status, and hides again once it does', async ({
    page,
  }) => {
    await createIssueTracker(page, 'Bugs');

    await expect(column(page, 'No status')).not.toBeVisible();

    const todo = column(page, 'todo');
    await addCard(page, todo, 'Untriaged issue');

    // Clear its status by dragging it into the "No status" column, which
    // only mounts once the drag has activated.
    await dndDragToLateMountedTarget(
      page,
      cardIn(todo, 'Untriaged issue'),
      'kanban-column-body',
    );

    const noStatus = column(page, 'No status');
    await expect(noStatus).toBeVisible();
    await expect(cardIn(noStatus, 'Untriaged issue')).toBeVisible();

    // Give it a status back — the column should hide again once it's empty.
    await dndDrag(
      page,
      cardIn(noStatus, 'Untriaged issue'),
      todo.getByTestId('kanban-column-body'),
    );

    await expect(column(page, 'No status')).not.toBeVisible();
  });

  test(
    'add a card, drag it between columns, and it persists',
    smoke,
    async ({ page }) => {
      await createIssueTracker(page, 'Bugs');

      const todo = column(page, 'todo');
      const doing = column(page, 'doing');

      await addCard(page, todo, 'Login button misaligned');

      // Starts in todo, not doing.
      await expect(cardIn(todo, 'Login button misaligned')).toBeVisible();
      await expect(cardIn(doing, 'Login button misaligned')).toHaveCount(0);

      // Drag from todo onto the doing column's card list.
      await dndDrag(
        page,
        cardIn(todo, 'Login button misaligned'),
        doing.getByTestId('kanban-column-body'),
      );

      // Now in doing, gone from todo.
      await expect(cardIn(doing, 'Login button misaligned')).toBeVisible();
      await expect(cardIn(todo, 'Login button misaligned')).toHaveCount(0);

      // The column move is a preview until `set()` writes the tag. Don't reload
      // until the resource actually holds Doing — otherwise OPFS still has Todo.
      await waitForCardStatus(page, 'Login button misaligned', doing);

      // Survives a reload (the status change was persisted to the resource).
      await reloadReconnected(page);
      await expect(page.getByTestId('kanban-board')).toBeVisible({
        timeout: 30_000,
      });
      await expect(
        column(page, 'doing').getByTestId('kanban-card').filter({
          hasText: 'Login button misaligned',
        }),
      ).toBeVisible({ timeout: 15_000 });
    },
  );

  test('a task added from another view starts in the default lane', async ({
    page,
  }) => {
    await createTableFromDialog(page, {
      template: /Project tasks/,
      name: 'Chores',
    });
    await expect(page.getByTestId('kanban-board')).toBeVisible();

    // The template makes Todo the lane new tasks start in.
    await expect(
      column(page, 'todo').getByTestId('kanban-column-default'),
    ).toBeVisible();

    const addOnToday = async (title: string) => {
      await page.getByRole('tab', { name: 'Schedule' }).click();
      const today = new Date();
      const todayKey = [
        today.getFullYear(),
        String(today.getMonth() + 1).padStart(2, '0'),
        String(today.getDate()).padStart(2, '0'),
      ].join('-');
      const todayCell = page.locator(
        `[data-testid="calendar-day"][data-date="${todayKey}"]`,
      );
      await todayCell.hover();
      await todayCell.getByTestId('calendar-day-add').click();
      const input = todayCell.getByPlaceholder('New item…');
      await input.fill(title);
      await input.press('Enter');
      await expect(
        todayCell.getByTestId('calendar-event').filter({ hasText: title }),
      ).toBeVisible();
      await page.getByRole('tab', { name: 'Board' }).click();
      await expect(page.getByTestId('kanban-board')).toBeVisible();
    };

    // Added on the calendar, it still lands in Todo rather than "No status".
    await addOnToday('Water the plants');
    await expect(
      cardIn(column(page, 'todo'), 'Water the plants'),
    ).toBeVisible();
    await expect(column(page, 'No status')).not.toBeVisible();

    // Another lane can be made the default from its menu.
    const doing = column(page, 'doing');
    await doing.getByRole('button', { name: 'Lane options' }).click();
    await page.getByTestId('menu-item-default-lane').click();
    await expect(doing.getByTestId('kanban-column-default')).toBeVisible();
    await expect(
      column(page, 'todo').getByTestId('kanban-column-default'),
    ).toHaveCount(0);

    await addOnToday('Take out the bins');
    await expect(cardIn(doing, 'Take out the bins')).toBeVisible();

    // The All tasks breakdown counts rows per status. Neither task has an
    // Estimate, which the view sums; that sum's own count once read as
    // "0 rows" under every status.
    await page.getByRole('tab', { name: 'All tasks' }).click();
    const breakdown = page.getByTestId('table-breakdown');
    await expect(breakdown).toBeVisible({ timeout: 30_000 });
    await expect(breakdown.getByText('1 rows')).toHaveCount(2, {
      timeout: 30_000,
    });
    await expect(breakdown).not.toContainText('0 rows');
  });

  test('clicking a card opens it in the expanded modal (not full-screen)', async ({
    page,
  }) => {
    await createIssueTracker(page, 'Bugs');

    const todo = column(page, 'todo');
    await addCard(page, todo, 'Open me in a modal');

    const card = cardIn(todo, 'Open me in a modal');
    await card.hover();
    await card.getByRole('button', { name: 'Open' }).click();

    // A modal dialog opens over the board with the row's properties…
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText('Open me in a modal');
    await expect(dialog).toContainText('Assignee');

    // …and it's a modal, not a navigation: still on the table URL.
    await expect(page).toHaveURL(/\/app\/show/);
    await expect(page.getByTestId('kanban-board')).toBeVisible();
  });

  test('clicking a card title edits it inline', async ({ page }) => {
    await createIssueTracker(page, 'Bugs');

    const todo = column(page, 'todo');
    await addCard(page, todo, 'Old title');

    // Click the title text → it becomes an input.
    await cardIn(todo, 'Old title').getByText('Old title').click();
    const titleInput = todo.getByRole('textbox').first();
    await titleInput.fill('New title');
    await titleInput.press('Enter');

    await expect(cardIn(todo, 'New title')).toBeVisible();
    await reloadReconnected(page);
    await expect(page.getByTestId('kanban-board')).toBeVisible({
      timeout: 30_000,
    });
    await expect(cardIn(column(page, 'todo'), 'New title')).toBeVisible({
      timeout: 15_000,
    });
  });

  test('typing a card title keystroke by keystroke keeps the editor', async ({
    page,
  }) => {
    await createIssueTracker(page, 'Bugs');

    const todo = column(page, 'todo');
    await addCard(page, todo, 'Typo');
    // Pin the card by subject: its text changes while we type.
    const subject = await cardIn(todo, 'Typo').getAttribute(
      'data-kanban-card-subject',
    );
    const card = todo.locator(`[data-kanban-card-subject="${subject}"]`);
    const heightBefore = (await card.boundingBox())?.height;

    await card.getByTestId('kanban-card-title').click();
    const titleInput = card.getByTestId('kanban-card-title-input');
    await expect(titleInput).toBeFocused();

    // The editor takes the title's exact box: a card that resizes shifts
    // the cards below it, and the next click lands on the wrong one.
    const heightEditing = (await card.boundingBox())?.height;
    expect(
      Math.abs((heightEditing ?? 0) - (heightBefore ?? 0)),
    ).toBeLessThanOrEqual(1);

    // Real keystrokes, not `fill`: Space and Enter used to bubble to the
    // card and start a keyboard drag, eating the space and the focus.
    await titleInput.press('ControlOrMeta+a');
    await titleInput.pressSequentially('Fix the login bug');
    await expect(titleInput).toBeFocused();
    await expect(titleInput).toHaveValue('Fix the login bug');
    await titleInput.press('Enter');

    await expect(cardIn(todo, 'Fix the login bug')).toBeVisible();
    await expect(page.getByRole('dialog')).toHaveCount(0);

    // Escape throws the draft away.
    await card.getByTestId('kanban-card-title').click();
    await expect(titleInput).toBeFocused();
    await titleInput.pressSequentially(' later');
    await titleInput.press('Escape');
    await expect(titleInput).toHaveCount(0);
    await expect(
      todo.getByTestId('kanban-card-title').filter({ hasText: 'later' }),
    ).toHaveCount(0);

    await reloadReconnected(page);
    await expect(page.getByTestId('kanban-board')).toBeVisible({
      timeout: 30_000,
    });
    await expect(cardIn(column(page, 'todo'), 'Fix the login bug')).toBeVisible(
      { timeout: 15_000 },
    );
  });

  test('right-clicking a card opens the resource context menu', async ({
    page,
  }) => {
    await createIssueTracker(page, 'Bugs');

    const todo = column(page, 'todo');
    await addCard(page, todo, 'Right click me');

    await cardIn(todo, 'Right click me').click({ button: 'right' });

    // The same actions as the navbar "More" menu, opened at the cursor.
    const menu = page.getByRole('menu');
    await expect(menu).toBeVisible();
    await expect(menu.getByTestId('menu-item-history')).toBeVisible();
    await expect(menu.getByTestId('menu-item-share')).toBeVisible();
  });

  test('context menu keyboard navigation advances and closes', async ({
    page,
  }) => {
    await createIssueTracker(page, 'Bugs');
    const todo = column(page, 'todo');
    await addCard(page, todo, 'KB nav');

    await cardIn(todo, 'KB nav').click({ button: 'right' });
    await expect(page.getByRole('menu')).toBeVisible();

    // The right-click menu is searchable, so focus stays in its filter input
    // and the keyboard selection is the item marked `data-selected`.
    const activeId = () =>
      page.evaluate(
        () =>
          document
            .querySelector('[role="menuitem"][data-selected="true"]')
            ?.getAttribute('data-testid') ?? null,
      );

    await page.keyboard.press('ArrowDown');
    const first = await activeId();
    await page.keyboard.press('ArrowDown');
    const second = await activeId();

    // Each arrow moves the selection — the bug was it sticking after the first.
    expect(first).toBeTruthy();
    expect(second).toBeTruthy();
    expect(second).not.toBe(first);

    await page.keyboard.press('Escape');
    await expect(page.getByRole('menu')).toHaveCount(0);
  });

  test('right-click menu actions (use in code, add to chat) work', async ({
    page,
  }) => {
    await createIssueTracker(page, 'Bugs');
    const todo = column(page, 'todo');
    await addCard(page, todo, 'Action card');

    // "Use in code" opens a dialog (for the card's own subject).
    await cardIn(todo, 'Action card').click({ button: 'right' });
    await page.getByTestId('menu-item-useInCode').click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).toHaveCount(0);

    // "Start AI Chat" opens the AI sidebar — proves the menu is mounted inside
    // the AI-sidebar provider (it wasn't before, so this action no-oped).
    await cardIn(todo, 'Action card').click({ button: 'right' });
    await page.getByTestId('menu-item-addToChat').click();
    await expect(page.getByTestId('ai-sidebar')).toHaveAttribute(
      'data-open',
      '',
    );
  });

  test('view tab menu: change type, duplicate, and delete', async ({
    page,
  }) => {
    await createIssueTracker(page, 'Bugs');

    const boardTab = page.getByRole('tab', { name: 'Board' });

    // Clicking the already-active tab opens its context menu.
    await boardTab.click();
    await expect(page.getByTestId('menu-item-duplicate')).toBeVisible();

    // Duplicate the Board view → a "Board copy" tab appears.
    await page.getByTestId('menu-item-duplicate').click();
    const copyTab = page.getByRole('tab', { name: 'Board copy' });
    await expect(copyTab).toBeVisible();

    // Duplication persists the view before navigating to it. Wait for that
    // navigation so the click opens the active tab's menu.
    await expect(copyTab).toHaveAttribute('aria-selected', 'true');

    // Change type Kanban → Table on the copy. "Change this view to" is only
    // offered while another view of the type remains (#1902), which the
    // original Board view now is.
    await copyTab.click();
    await page.getByTestId('menu-item-kind-table').click();
    await expect(page.getByTestId('kanban-board')).toHaveCount(0);

    // Delete the copy via its tab menu + confirmation dialog.
    await copyTab.click();
    await page.getByTestId('menu-item-delete').click();
    await page
      .getByRole('dialog')
      .getByRole('button', { name: 'Delete' })
      .click();
    await expect(copyTab).toHaveCount(0);
    await expect(boardTab).toBeVisible();
  });
});
