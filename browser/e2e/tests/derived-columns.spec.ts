import { test, expect, type Page } from './fixtures';
import {
  before,
  createTableFromDialog,
  inDialog,
  setGridCell,
  waitForGridMounted,
  waitForSynced,
} from './test-utils';

/** The grid row containing `text`. */
const row = (page: Page, text: string) =>
  page.getByRole('row').filter({ hasText: text });

/** Opens Add column → Computed and fills in the dialog. */
async function addComputedColumn(
  page: Page,
  spec: {
    kind: string;
    name: string;
    /** Argument name → the option label to pick. */
    args: Record<string, string>;
    /** Argument name → the number to type, for "A fixed number…" arguments. */
    literals?: Record<string, string>;
  },
) {
  await page.getByRole('button', { name: 'Add column' }).click();
  await page.getByTestId('menu-item-computed').click();

  await inDialog(page, async () => {
    await page.getByTestId('derived-kind').selectOption(spec.kind);
    await page.getByTestId('derived-label').fill(spec.name);

    for (const [arg, label] of Object.entries(spec.args)) {
      await page.getByTestId(`derived-arg-${arg}`).selectOption({ label });
    }

    for (const [arg, value] of Object.entries(spec.literals ?? {})) {
      await page.getByTestId(`derived-literal-${arg}`).fill(value);
    }

    // By test id, not by its label: the button's text is translated, so a
    // missing catalog entry would fail this as if the feature were broken.
    await page.getByTestId('derived-save').click();
  });
}

/** Types a value into one grid cell, addressed by its row and column index. */
async function setCell(
  page: Page,
  rowIndex: number,
  columnIndex: number,
  value: string,
  _opts: { replace?: boolean } = {},
) {
  await setGridCell(page, rowIndex, columnIndex, value, { match: /\S/ });
}

test.describe('computed columns', () => {
  test.beforeEach(before);

  test('a human can add, edit and remove one, in any table view', async ({
    page,
  }) => {
    // The Time tracker template gives two timestamp columns and a quick way to
    // fill them: start an entry and stop it.
    await createTableFromDialog(page, {
      template: /Time tracker/,
      name: 'Computed columns',
    });

    await expect(page.getByTestId('timer-new-input')).toBeVisible();
    await waitForGridMounted(page);

    await page.getByTestId('timer-new-input').fill('Write docs');
    await page.getByTestId('timer-start-new').click();
    const entry = row(page, 'Write docs');
    await expect(entry).toBeVisible();
    await entry.getByTestId('timer-stop').click();
    await expect(entry.getByTestId('timer-resume')).toBeVisible();

    // Everything below happens in the plain table view — computed columns are
    // not a timer feature.
    await page.getByRole('tab', { name: 'All entries' }).click();
    await expect(page.getByTestId('timer-new-input')).toHaveCount(0);
    await expect(page.getByRole('grid')).toBeVisible();

    // A column computed from two date columns.
    await addComputedColumn(page, {
      kind: 'difference',
      name: 'Logged',
      args: { from: 'Start', to: 'End' },
    });

    await expect(
      page.getByRole('button', { name: 'Edit computed column' }),
    ).toBeVisible();
    await expect(
      row(page, 'Write docs').getByTestId('derived-logged'),
    ).toHaveText(/^\d+:\d{2}:\d{2}$/);

    // And one whose second argument is a number typed into the dialog rather
    // than read off a column.
    await addComputedColumn(page, {
      kind: 'offset',
      name: 'Next due',
      args: { from: 'Start', days: 'A fixed number…' },
      literals: { days: '14' },
    });

    await expect(
      row(page, 'Write docs').getByTestId('derived-next-due'),
    ).toHaveText(/\d{2}\/\d{2}\/\d{4}/);

    // Renaming keeps the column (and its value): it is the same spec, edited.
    const logged = await row(page, 'Write docs')
      .getByTestId('derived-logged')
      .textContent();
    await page
      .getByRole('button', { name: 'Edit computed column' })
      .first()
      .click();
    await page.getByTestId('menu-item-edit').click();
    await inDialog(page, async () => {
      await page.getByTestId('derived-label').fill('Time spent');
      await page.getByTestId('derived-save').click();
    });

    await expect(page.getByText('Time spent')).toBeVisible();
    await expect(
      row(page, 'Write docs').getByTestId('derived-logged'),
    ).toHaveText(logged ?? '');

    // Both live on the View, so they survive a reload.
    await page.reload();
    await expect(page.getByRole('grid')).toBeVisible();
    await expect(page.getByText('Time spent')).toBeVisible();
    await expect(
      row(page, 'Write docs').getByTestId('derived-next-due'),
    ).toBeVisible();

    // Removing one leaves the other alone — and removes no data.
    await page
      .getByRole('button', { name: 'Edit computed column' })
      .first()
      .click();
    await page.getByTestId('menu-item-remove').click();
    await inDialog(page, async (_dialog, closeDialogWith) => {
      await closeDialogWith('Remove');
    });

    await expect(
      row(page, 'Write docs').getByTestId('derived-logged'),
    ).toHaveCount(0);
    await expect(
      row(page, 'Write docs').getByTestId('derived-next-due'),
    ).toBeVisible();
    await expect(
      page.getByRole('gridcell', { name: 'Write docs' }),
    ).toBeVisible();
  });

  test('a computed column follows an edit to the column it derives from', async ({
    page,
  }) => {
    test.slow();

    // Inventory's Value is Quantity × Unit price, so typing either one has to
    // move it — in place, without a reload. A computed cell used to keep
    // whatever it computed when it mounted, because reading the row during
    // render let the React Compiler cache the result on a resource identity
    // that never changes.
    await createTableFromDialog(page, {
      template: /Inventory/,
      name: 'Live values',
    });
    await waitForGridMounted(page);
    await setCell(page, 2, 2, 'Bolts');
    await setCell(page, 2, 4, '4');
    await setCell(page, 2, 5, '0.25');

    // Reload once, so the row under test is a saved row rather than the trailing
    // draft — a draft's cells are a separate story (see the gaps list).
    await waitForSynced(page);
    await page.reload();
    await waitForGridMounted(page);

    const bolts = row(page, 'Bolts');
    await expect(bolts.getByTestId('derived-value')).toHaveText('1', {
      timeout: 15_000,
    });

    // Change one factor: the product follows, in place, with no reload. This is
    // the assertion the old behaviour could not pass.
    await setCell(page, 2, 4, '8', { replace: true });
    await expect(bolts.getByTestId('derived-value')).toHaveText('2', {
      timeout: 15_000,
    });
  });

  test('a computed column can be resized, and the width sticks', async ({
    page,
  }) => {
    // The Time tracker template's timer view has both kinds of view-added
    // column: a configured Duration and the timer's own Start/Stop.
    await createTableFromDialog(page, {
      template: /Time tracker/,
      name: 'Resizable',
    });

    await expect(page.getByTestId('timer-new-input')).toBeVisible();
    await waitForGridMounted(page);

    // A timer view leads with its own columns: Duration (2) and the Start/Stop
    // button (3), then the stored ones.
    const duration = page.locator('[role="columnheader"][aria-colindex="2"]');
    const timer = page.locator('[role="columnheader"][aria-colindex="3"]');

    const widthOf = async (column: typeof duration) =>
      Math.round((await column.boundingBox())!.width);

    // Both start narrower than a text column — a duration and a button don't
    // need 300px.
    expect(await widthOf(duration)).toBeLessThan(200);
    expect(await widthOf(timer)).toBeLessThan(120);

    /** Drags a column's right edge by `by` pixels. */
    const resizeBy = async (column: typeof duration, by: number) => {
      const box = (await column.boundingBox())!;
      const x = box.x + box.width - 1;
      const y = box.y + box.height / 2;
      await page.mouse.move(x, y);
      await page.mouse.down();
      await page.mouse.move(x + by, y, { steps: 10 });
      await page.mouse.up();
      await expect.poll(() => widthOf(column)).not.toBe(Math.round(box.width));
    };

    await resizeBy(duration, 90);
    const widened = await widthOf(duration);
    expect(widened).toBeGreaterThan(200);

    // The timer's own column is narrower than the grid's old 100px floor, which
    // used to snap it wider instead of resizing it.
    await resizeBy(timer, -25);
    const narrowed = await widthOf(timer);
    expect(narrowed).toBeLessThan(70);

    await waitForSynced(page);
    await page.reload();
    await waitForGridMounted(page);

    await expect
      .poll(() => widthOf(duration), { timeout: 15_000 })
      .toBe(widened);
    await expect.poll(() => widthOf(timer), { timeout: 15_000 }).toBe(narrowed);
  });

  test('columns can be reordered, including the ones a view adds', async ({
    page,
  }) => {
    await createTableFromDialog(page, {
      template: /Time tracker/,
      name: 'Reorderable',
    });

    await expect(page.getByTestId('timer-new-input')).toBeVisible();
    await waitForGridMounted(page);

    const headings = () =>
      page.evaluate(() =>
        Array.from(document.querySelectorAll('[role="columnheader"]'))
          .slice(1)
          .map(el => (el.textContent ?? '').replace('Drag column', '').trim()),
      );

    // A timer view leads with its own columns.
    expect((await headings()).slice(0, 3)).toEqual([
      'Duration',
      'Timer',
      'name',
    ]);

    // Drag the Duration heading past `name` by its handle.
    const handle = page
      .locator('[role="columnheader"][aria-colindex="2"]')
      .getByRole('button', { name: 'Drag column' });
    const name = page.locator('[role="columnheader"][aria-colindex="4"]');
    const from = (await handle.boundingBox())!;
    const to = (await name.boundingBox())!;

    await page.mouse.move(from.x + from.width / 2, from.y + from.height / 2);
    await page.mouse.down();
    await page.mouse.move(to.x + to.width - 5, to.y + to.height / 2, {
      steps: 15,
    });
    await page.mouse.up();
    await expect
      .poll(async () => {
        const h = await headings();

        return h.indexOf('Duration') > h.indexOf('name');
      })
      .toBe(true);

    const reordered = await headings();
    expect(reordered.indexOf('Duration')).toBeGreaterThan(
      reordered.indexOf('name'),
    );

    await waitForSynced(page);
    await page.reload();
    await waitForGridMounted(page);

    await expect.poll(headings, { timeout: 15_000 }).toEqual(reordered);
  });
  test('a computed column can be filtered on, in a unit that reads', async ({
    page,
  }) => {
    test.slow();

    // Two entries: one logged for a moment, one still running. Their Duration is
    // computed, so the store has to evaluate it to answer this filter.
    await createTableFromDialog(page, {
      template: /Time tracker/,
      name: 'Filtered durations',
    });

    await expect(page.getByTestId('timer-new-input')).toBeVisible();
    await waitForGridMounted(page);

    // Log the short one and stop it...
    await page.getByTestId('timer-new-input').fill('Short task');
    await page.getByTestId('timer-start-new').click();
    await expect(row(page, 'Short task')).toBeVisible();
    await row(page, 'Short task').getByTestId('timer-stop').click();
    await expect(
      row(page, 'Short task').getByTestId('timer-resume'),
    ).toBeVisible();

    // ...then start one that keeps running, so its duration grows on its own.
    // (Starting it first would have stopped the other: "one at a time" is on.)
    await page.getByTestId('timer-new-input').fill('Long task');
    await page.getByTestId('timer-start-new').click();
    await expect(row(page, 'Long task')).toBeVisible();

    // Filter for entries logged for at least an hour. Neither qualifies, which is
    // the point: the value is asked for in HOURS, not milliseconds.
    await page.getByTitle('Filter', { exact: true }).click();
    await page.getByRole('menuitem', { name: 'Duration', exact: true }).click();
    await page.getByTestId('derived-filter-value').fill('1');
    await page.keyboard.press('Escape');

    await expect(row(page, 'Short task')).toHaveCount(0, { timeout: 15_000 });
    await expect(row(page, 'Long task')).toHaveCount(0);
    // The chip says what it filtered by, in the unit it asked for.
    await expect(page.getByTestId('filter-chip')).toContainText('1 hours');

    // The constraint lives on the View like any other filter, so it survives a
    // reload — including the unit it was typed in.
    //
    // Wait for the View resource to actually hold the constraint before waiting
    // on the sync queue: the write is debounced, and `pendingDirtyCount` is
    // still 0 in the window before the commit is queued at all.
    await page.waitForFunction(
      () => {
        for (const res of window.store?.resources.values() ?? []) {
          const stored = res?.get?.(
            'https://atomicdata.dev/properties/view-filters',
          ) as { derived?: string }[] | undefined;

          if (stored?.some(f => f.derived !== undefined)) {
            return true;
          }
        }

        return false;
      },
      undefined,
      { timeout: 30_000 },
    );
    await waitForSynced(page, 30_000);
    await page.reload({ waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('grid')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId('filter-chip')).toContainText('1 hours');
    // Same budget as the pre-reload assertions above, because this side has
    // strictly more to do: the chip only proves the View loaded, and every
    // row's Duration still has to be recomputed before the filter can exclude
    // it. There is nothing positive to await instead — the expected end state
    // is an empty grid, so `toHaveCount(0)` polling for it IS the signal.
    await expect(row(page, 'Short task')).toHaveCount(0, { timeout: 15_000 });
    await expect(row(page, 'Long task')).toHaveCount(0, { timeout: 15_000 });

    // Removing it brings both entries back, the running one included.
    await page.getByTestId('filter-chip').click();
    await page.getByTitle('Remove filter').click();

    await expect(row(page, 'Short task')).toBeVisible({ timeout: 15_000 });
    await expect(row(page, 'Long task')).toBeVisible();
  });
});
