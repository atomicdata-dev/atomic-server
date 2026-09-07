import { test, expect, type Page } from './fixtures';
import {
  newResource,
  before,
  createTableFromDialog,
  enterGridEdit,
  focusCell,
  inDialog,
  reloadGrid,
  tabToNextGridCell,
  typeInActiveGridCell,
  waitForGridMounted,
  waitForSynced,
  waitForTableBuild,
  smoke,
} from './test-utils';

/**
 * Creates a blank table from the drive page's quick-create button and leaves
 * the caller on its grid, out of the title's edit mode and ready to type.
 */
async function createBlankTable(page: Page, name: string) {
  await page.getByTitle('New Table').first().click();
  await page.getByPlaceholder('New Table').fill(name);
  await page.locator('dialog[open] button:has-text("Create")').click();
  // The dialog carries the wait: it closes once the table exists and the app
  // has navigated to it, so nothing below races the create.
  await waitForTableBuild(page);
  // EditableTitle auto-enters edit mode on creation (renders an input); when
  // not editing it renders an h1. Match either form by test-id.
  await expect(page.getByTestId('editable-title').first()).toBeVisible();
  // Exit edit mode so subsequent keyboard actions (Tab to move into the grid)
  // don't get swallowed by the title input.
  await page.keyboard.press('Escape');
  await expect(page.getByRole('gridcell').first()).toBeVisible();
}

type Row = {
  name: string;
  date: string;
  number: string;
  checkbox: boolean;
  select: string;
};

test.describe('tables', async () => {
  test.beforeEach(before);

  test('table dialog pre-fills name and focuses input', async ({ page }) => {
    await newResource('table', page);
    const input = page.getByPlaceholder('New Table');
    await expect(input).toHaveValue('Table');
    await expect(input).toBeFocused();
  });

  // FLAKY (dagger CI + remote CI): the long table-fill choreography has
  // many sub-steps (column dialogs, tag picker, sequential row fills)
  // and any of them can blow the action budget under dagger contention.
  // Most-frequent failure: the gridcell Visual→Edit-mode transition
  // races, leaving the cell-input not focused. Investigate: replace the
  // double-click pattern with a single-click + explicit Edit-mode
  // assertion, or use the keyboard-driven flow exclusively.
  test('create and fill', smoke, async ({ page }) => {
    test.slow();

    const newColumn = async (type: string) => {
      await page.getByRole('button', { name: 'Add column' }).click();
      await page.click(`text=${type}`);
    };

    const tab = async () => {
      await tabToNextGridCell(page);
    };

    const createTag = async (emote: string, name: string) => {
      await page.getByPlaceholder('New tag').last().fill(name);
      await page.getByTitle('Pick an emoji').last().click();
      await page.getByPlaceholder('Search', { exact: true }).fill(emote);
      await page.getByRole('button', { name: emote }).click();
      await page.getByTitle('Add tag').last().click();
      await expect(page.getByRole('button', { name })).toBeVisible();
    };

    const pickTag = async (name: string) => {
      // Cell focus on the tag column opens the tag picker, but under dagger
      // CPU contention the popup mount can lag past the default 5s actionTimeout.
      // Bump the wait, and press Enter as a fallback open trigger if it
      // hasn't appeared yet — both paths land on the same picker.
      const filter = page.getByPlaceholder('filter tags');

      if (!(await filter.isVisible({ timeout: 2000 }).catch(() => false))) {
        await page.keyboard.press('Enter');
      }

      await expect(filter).toBeVisible({ timeout: 15000 });
      await page.keyboard.type(name);
      await page.keyboard.press('Enter');
      await page.keyboard.press('Escape');
      await expect(filter).not.toBeVisible();
    };

    const fillRow = async (currentRowNumber: number, row: Row) => {
      const { name, date, number, checkbox, select } = row;
      const rowIndex = currentRowNumber + 1;
      // Position on this row's first cell before editing. The tag picker's
      // Escape (in pickTag, below) drops the grid out of Edit into Visual
      // mode, so we can't rely on Tab wrapping from the previous row's last
      // cell to land here in edit mode. Click the target cell directly,
      // mirroring the initial cell setup — the trailing empty row is always
      // present once the previous row has gained content.
      //
      // The grid remounts rows while they materialize; a locator that was
      // attached a moment ago can detach mid-scroll. Retry until focus
      // lands in this cell's editor.
      await expect(async () => {
        const rowFirstCell = page.locator(
          `[aria-rowindex="${rowIndex}"] > [aria-colindex="2"]`,
        );
        await rowFirstCell.scrollIntoViewIfNeeded();
        await rowFirstCell.click();
        await expect(rowFirstCell).toBeFocused({ timeout: 2_000 });
        await page.keyboard.press('Enter');
        await expect(
          page.locator(
            `[aria-rowindex="${rowIndex}"] > [aria-colindex="2"] > input`,
          ),
        ).toBeFocused({ timeout: 2_000 });
      }).toPass({ timeout: 15_000 });
      const nameInput = page.locator(
        `[aria-rowindex="${rowIndex}"] > [aria-colindex="2"] > input`,
      );
      await nameInput.fill(name);
      await expect(nameInput).toHaveValue(name);
      await tab();
      await expect(
        page.getByRole('rowheader', { name: `${currentRowNumber + 1}` }),
      ).toBeAttached();

      await page.keyboard.type(date);
      await tab();
      await page.keyboard.type(number);
      await tab();

      if (checkbox) {
        await page.keyboard.press('Space');

        await expect(
          page.locator(`[aria-rowindex="${rowIndex}"]`).getByRole('checkbox'),
          "Checkbox isn't checked",
        ).toBeChecked();
      } else {
        await expect(
          page.locator(`[aria-rowindex="${rowIndex}"]`).getByRole('checkbox'),
          'Checkbox is checked but should not be',
        ).not.toBeChecked();
      }

      await tab();
      await pickTag(select);
      // pickTag ends in Visual mode (its Escape closes the picker and exits
      // edit), so the row is complete here — the next fillRow re-positions
      // itself by clicking. Just confirm this row's name landed.
      await expect(
        page.getByRole('gridcell', { name: row.name }),
        `${row.name} row not visible`,
      ).toBeVisible();
    };

    // --- Test Start ---
    // Name table (pre-filled with "table", replace it)
    const tableName = 'Made up music genres';
    await createTableFromDialog(page, { name: tableName });
    // Newly-created resources auto-enter edit mode, so the title renders as
    // an input. Match either form.
    await expect(
      page
        .getByTestId('editable-title')
        .and(page.locator(`:text-is("${tableName}"), [value="${tableName}"]`))
        .first(),
    ).toBeVisible();
    // Exit edit mode so subsequent keyboard actions (Tab to move into the
    // grid) don't get swallowed by the title input.
    await page.keyboard.press('Escape');

    const dateColumnName = 'Existed since';
    await newColumn('Date');
    await inDialog(page, async (dialog, closeDialogWith) => {
      await expect(page.locator('text=New Date Column')).toBeVisible();
      await dialog.getByPlaceholder('New Column').fill(dateColumnName);
      await dialog.getByLabel('Long').click();
      await closeDialogWith('Create');
    });

    await expect(
      page.getByRole('button', { name: dateColumnName }),
    ).toBeVisible({ timeout: 15000 });

    await newColumn('Number');
    const numberColumnName = 'Number of tracks';

    await inDialog(page, async (dialog, closeDialogWith) => {
      await expect(page.locator('text=New Number Column')).toBeVisible();
      await dialog.getByPlaceholder('New Column').fill(numberColumnName);
      await closeDialogWith('Create');
    });

    await expect(
      page.getByRole('button', { name: numberColumnName }),
    ).toBeVisible();

    await newColumn('Checkbox');
    const checkboxColumnName = 'Approved by W3C';

    await inDialog(page, async (dialog, closeDialogWith) => {
      await expect(page.locator('text=New Checkbox Column')).toBeVisible();
      await dialog.getByPlaceholder('New Column').fill(checkboxColumnName);
      await closeDialogWith('Create');
    });

    await expect(
      page.getByRole('button', { name: checkboxColumnName }),
    ).toBeVisible();

    await newColumn('Select');
    const selectColumnName = 'Descriptive words';

    await inDialog(page, async (dialog, closeDialogWith) => {
      await expect(page.locator('text=New Select Column')).toBeVisible();
      await dialog.getByPlaceholder('New Column').fill(selectColumnName);

      await createTag('😤', 'wild');
      await createTag('😵‍💫', 'dreamy');
      await createTag('🤨', 'wtf');
      await closeDialogWith('Create');
    });

    await expect(
      page.getByRole('button', { name: selectColumnName }),
    ).toBeVisible();

    // Wait for all pending commits to drain into the server before reload.
    // 'networkidle' is unreliable on SPAs with persistent WebSocket
    // connections (commit subscriptions, the open WS, etc.). The dirty
    // queue is the actual saved-to-server signal.
    await waitForSynced(page);
    await page.reload();
    await expect(
      page.getByRole('button', { name: selectColumnName }),
    ).toBeVisible();

    const rows = [
      {
        name: 'Progressive Pizza House',
        date: '04032000',
        number: '10',
        checkbox: true,
        select: 'dreamy',
      },
      {
        name: 'Drum or Bass',
        date: '15051980',
        number: '3000035',
        checkbox: false,
        select: 'wild',
      },
      {
        name: 'Mumble Punk',
        date: '13051965',
        number: '60',
        checkbox: true,
        select: 'wtf',
      },
    ];
    // Wait for the collection's placeholder row before fillRow starts
    // clicking. fillRow owns all positioning — clicking an already-active
    // cell enters edit mode instead of just focusing it, so we must not
    // pre-click here. 30s, not the 10s default: the first data row renders
    // after the new columns' commits clear the ClientDb worker queue.
    await waitForGridMounted(page);

    for (const [index, row] of rows.entries()) {
      await fillRow(index + 1, row);
    }

    await expect(
      page.getByRole('gridcell', { name: '😵‍💫 dreamy' }),
    ).toBeVisible();
    await expect(page.getByRole('gridcell', { name: '😤 wild' })).toBeVisible();
    await expect(page.getByRole('gridcell', { name: '🤨 wtf' })).toBeVisible();

    // Edit first cell content: click the first row's name cell, then type to
    // replace it (typing in Visual mode enters edit mode from empty). Clicking
    // is deterministic — the previous ArrowUp navigation assumed the cursor
    // ended on the name column, which the Tab-wrap no longer guarantees.
    await page.keyboard.press('Escape');
    const firstNameCell = page.locator(
      '[aria-rowindex="2"] > [aria-colindex="2"]',
    );
    await firstNameCell.click();
    await expect(firstNameCell).toBeFocused();
    const newName = 'Progressive Peperoni Pizza House';
    await page.keyboard.type(newName);
    await page.keyboard.press('Escape');

    await expect(
      page.getByRole('gridcell', { name: rows[0].name }),
      "Old cell name shouldn't be visible",
    ).not.toBeVisible();

    await expect(
      page.getByRole('gridcell', { name: newName }),
      'New cell name not visible',
    ).toBeVisible();

    // Delete second row
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('ArrowLeft');
    await page.keyboard.press('Backspace');

    await expect(
      page.getByRole('gridcell', { name: 'Drum or Bass' }),
    ).not.toBeVisible();
  });

  test('fast row entry - rapidly adding rows with Enter', async ({ page }) => {
    test.slow();
    // Use the quick-create "New Table" button on the drive page directly.
    await createBlankTable(page, 'Fast Entry Test');

    const firstCell = page.getByRole('gridcell').first();
    await focusCell(page, firstCell);

    // Enough rows to overflow the viewport and exercise react-window
    // virtualization + auto-scroll as new rows are added past the fold.
    const values = Array.from({ length: 40 }, (_, i) => `row${i + 1}`);

    // Type each value and immediately press Enter to move to the next row
    for (const value of values) {
      await enterGridEdit(page);
      await typeInActiveGridCell(page, value);
    }

    // Every Enter must have created a row. This is the regression guard for
    // the bug where, once rows overflowed the viewport, a list remount snapped
    // the scroll to the top, virtualized the active cell out, and silently
    // stopped adding rows. The grid is virtualized so we can't assert every
    // row is in the DOM — count the materialized resources in the store
    // instead. `+1` row in the grid is the trailing empty placeholder.
    const namedRowCount = () =>
      page.evaluate(() => {
        const NAME = 'https://atomicdata.dev/properties/name';

        return Array.from(window.store.resources?.values?.() ?? []).filter(
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (r: any) => /^row\d+$/.test(r.get?.(NAME) ?? ''),
        ).length;
      });

    await expect.poll(namedRowCount).toBe(values.length);

    // Exit edit mode
    await page.keyboard.press('Escape');

    // Wait for the two things the reload below actually depends on, rather
    // than for the aggregate counter to happen to reach zero.
    //
    // A row keeps a `_new:` subject until its materialize timer fires: it
    // exists in this tab and nowhere else, so the count above being right
    // says nothing about whether it would survive. And a materialized row
    // still has to reach the server. Assert both directly.
    await page.waitForFunction(
      expected => {
        const NAME = 'https://atomicdata.dev/properties/name';
        const rows = Array.from(
          window.store.resources?.values?.() ?? [],
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
        ).filter((r: any) => /^row\d+$/.test(r.get?.(NAME) ?? ''));

        if (rows.length !== expected) return false;

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        if (rows.some((r: any) => String(r.subject).startsWith('_new:'))) {
          return false;
        }

        return window.store.getSyncStatus().pendingDirtyCount === 0;
      },
      values.length,
      // Forty genesis commits + OPFS puts. 15s is enough on a quiet runner
      // and routinely not under dagger load; 30s still tripped on an idle
      // Mancave runner (2026-09-02), so match the post-reload wait below.
      { timeout: 60_000 },
    );

    // Spot-check the bottom of the list is rendered (the active cell stayed in
    // view) — the last typed row must be visible right after entry.
    const last = values[values.length - 1];
    await expect(
      page.getByRole('gridcell', { name: last, exact: true }),
      `Last row "${last}" should be visible after entry`,
    ).toBeVisible();

    // Refresh and verify the rows persisted. The collection is virtualized, so
    // assert the loaded member count, then spot-check the first row (scroll to
    // top) and the last row (scroll to bottom).
    //
    // `reloadGrid`, not a bare `page.reload()`: forty rows just went through
    // materialize timers, outbox drains and OPFS persists, and a reload that
    // does not wait for materialization + the durability flush rolls the tail
    // of that work back (the CI-only "row40 missing after refresh").
    await reloadGrid(page);
    await expect(page.getByTestId('editable-title').first()).toBeVisible();

    // 30s, not the default: the post-reload re-drain queues forty rows of
    // writes ahead of the member query in the ClientDb worker, and on a
    // loaded runner that queue takes 15s+ to drain (measured ~18.5s in the
    // instrumented CI runs). Tracked as the OPFS write-amplification issue —
    // when write count drops, this budget can too.
    await expect.poll(namedRowCount, { timeout: 30000 }).toBe(values.length);

    // Same 30s budget as the count poll above, for the same reason: the
    // spot-checked rows render from hydrations queued behind the re-drain.
    const grid = page.getByRole('grid');
    await grid.evaluate(g => g.scrollIntoView({ block: 'start' }));
    await page.mouse.move(600, 300);
    await page.mouse.wheel(0, -5000); // scroll to top
    await expect(
      page.getByRole('gridcell', { name: 'row1', exact: true }),
      'First row should be visible after refresh',
    ).toBeVisible({ timeout: 30000 });

    await page.mouse.wheel(0, 5000); // scroll to bottom
    await expect(
      page.getByRole('gridcell', { name: last, exact: true }),
      `Last row "${last}" should be visible after refresh`,
    ).toBeVisible({ timeout: 30000 });
  });

  test('sorting reorders freshly-entered (virtual) rows', async ({ page }) => {
    test.slow();
    await createBlankTable(page, 'Sort Test');

    const firstCell = page.getByRole('gridcell').first();
    await focusCell(page, firstCell);

    // Enter rows whose names are NOT in alphabetical order.
    for (const name of ['gamma', 'alpha', 'beta']) {
      await enterGridEdit(page);
      await typeInActiveGridCell(page, name);
    }

    await page.keyboard.press('Escape');
    await waitForSynced(page);

    // Default sort is by creation time → insertion order: gamma is row 1.
    await expect(
      page
        .locator('[aria-rowindex="2"]')
        .getByRole('gridcell', { name: 'gamma', exact: true }),
      'Before sort, first row should be the first-entered ("gamma")',
    ).toBeVisible();

    // Click the "name" column header to sort by name (ascending).
    await page
      .getByRole('button', { name: 'name', exact: true })
      .first()
      .click();

    // After sort, the freshly-entered virtual rows must reorder: "alpha" first.
    await expect(
      page
        .locator('[aria-rowindex="2"]')
        .getByRole('gridcell', { name: 'alpha', exact: true }),
      'After sorting by name, first row should be "alpha"',
    ).toBeVisible();
  });

  test('Shift+Enter inserts a row below the current row', async ({ page }) => {
    test.slow();
    await createBlankTable(page, 'Insert Below Test');

    const firstCell = page.getByRole('gridcell').first();
    await focusCell(page, firstCell);

    // Two rows via normal fast entry.
    for (const value of ['rowA', 'rowB']) {
      await enterGridEdit(page);
      await typeInActiveGridCell(page, value);
    }

    await page.keyboard.press('Escape');
    await waitForSynced(page);

    // Reload so the rows are collection members (positional insert targets
    // persisted rows; this-session virtual rows always append at the bottom).
    await page.reload();
    await expect(page.getByTestId('editable-title').first()).toBeVisible();
    await expect(page.getByText('rowA', { exact: true })).toBeVisible({
      timeout: 15000,
    });

    // Select rowA's name cell, then insert a row below it.
    await focusCell(page, page.getByText('rowA', { exact: true }));
    await page.keyboard.press('Shift+Enter');

    // The inserted row is persisted with a fractional sortOrder between rowA
    // and rowB, so rowB shifts from aria-rowindex 3 to 4 once it lands.
    await expect(
      page.locator('[aria-rowindex="4"]'),
      'rowB should shift down after inserting below rowA',
    ).toContainText('rowB', { timeout: 15000 });

    // The cursor moved to the inserted row; typing fills its name cell.
    await enterGridEdit(page);
    await typeInActiveGridCell(page, 'rowINSERTED');
    await page.keyboard.press('Escape');
    await waitForSynced(page);

    const expectOrder = async () => {
      await expect(page.locator('[aria-rowindex="2"]')).toContainText('rowA', {
        timeout: 15000,
      });
      await expect(page.locator('[aria-rowindex="3"]')).toContainText(
        'rowINSERTED',
        { timeout: 15000 },
      );
      await expect(page.locator('[aria-rowindex="4"]')).toContainText('rowB', {
        timeout: 15000,
      });
    };

    await expectOrder();

    // The order comes from the server's sortOrder→createdAt fallback axis, so
    // it must survive a reload.
    await page.reload();
    await expect(page.getByTestId('editable-title').first()).toBeVisible();
    await expectOrder();
  });

  test('Shift+Enter inserts among freshly typed (unsaved) rows', async ({
    page,
  }) => {
    test.slow();
    await createBlankTable(page, 'Insert Session Test');

    const firstCell = page.getByRole('gridcell').first();
    await focusCell(page, firstCell);

    for (const value of ['rowA', 'rowB']) {
      await enterGridEdit(page);
      await typeInActiveGridCell(page, value);
    }

    await page.keyboard.press('Escape');

    // Without reloading (rows are still session drafts), insert below rowA.
    await focusCell(page, page.getByText('rowA', { exact: true }));
    await page.keyboard.press('Shift+Enter');

    // The spliced virtual row renders immediately at aria-rowindex 3,
    // pushing rowB down; the cursor is on it.
    await expect(
      page.locator('[aria-rowindex="4"]'),
      'rowB should shift down after inserting below rowA',
    ).toContainText('rowB', { timeout: 15000 });
    // Enter edit mode explicitly (focuses the cell input) before typing —
    // typing into a just-mounted cell via the type-to-edit relay can race
    // its event-listener registration at automation speed.
    await enterGridEdit(page);
    await typeInActiveGridCell(page, 'rowMID');
    await page.keyboard.press('Escape');
    await waitForSynced(page);

    const expectOrder = async () => {
      await expect(page.locator('[aria-rowindex="2"]')).toContainText('rowA', {
        timeout: 15000,
      });
      await expect(page.locator('[aria-rowindex="3"]')).toContainText(
        'rowMID',
        { timeout: 15000 },
      );
      await expect(page.locator('[aria-rowindex="4"]')).toContainText('rowB', {
        timeout: 15000,
      });
    };

    await expectOrder();

    // The spliced row's minted sortOrder must make this order survive
    // materialization + reload — its createdAt (sign time) is later than
    // rowB's and would otherwise sort it last.
    await page.reload();
    await expect(page.getByTestId('editable-title').first()).toBeVisible();
    await expectOrder();
  });
});
