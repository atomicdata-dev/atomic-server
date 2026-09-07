import { test, expect, type Page } from './fixtures';
import {
  before,
  inDialog,
  pickFromMenu,
  waitForGridMounted,
  waitForSynced,
} from './test-utils';

const LOCALIZED_TEXT_DATATYPE =
  'https://atomicdata.dev/datatypes/localizedText';
const DATATYPE_PROP = 'https://atomicdata.dev/properties/datatype';
const NAME_PROP = 'https://atomicdata.dev/properties/name';

/** The header language chip of a LocalizedText column (not the navbar select). */
const chips = (page: Page) => page.locator('button[title="Content language"]');

const cell = (page: Page, rowIndex: number, colIndex: number) =>
  page.locator(`[aria-rowindex="${rowIndex}"] > [aria-colindex="${colIndex}"]`);

const waitForSaved = (page: Page) => waitForSynced(page);

/** Creates a table with the default name column plus a LocalizedText column. */
async function createLocalizedTable(
  page: Page,
  tableName: string,
  columnName: string,
) {
  await page.getByTitle('New Table').first().click();
  await page.getByPlaceholder('New Table').fill(tableName);
  await page.locator('dialog[open] button:has-text("Create")').click();
  await page.waitForURL(url => url.pathname.startsWith('/app/show'), {
    timeout: 15000,
  });
  await expect(page.getByTestId('editable-title').first()).toBeVisible({
    timeout: 15000,
  });
  // Exit title edit mode so keyboard input reaches the grid.
  await page.keyboard.press('Escape');

  await page.getByRole('button', { name: 'Add column' }).click();
  await page.click('text=Localized Text');
  await inDialog(page, async (dialog, closeDialogWith) => {
    await dialog.getByPlaceholder('New Column').fill(columnName);
    await closeDialogWith('Create');
  });

  await expect(page.getByRole('button', { name: columnName })).toBeVisible({
    timeout: 15000,
  });

  // Let TableEditor bind its handlers before the first cell click — the
  // click races React state initialization otherwise (same settle as
  // tables.spec).
  await expect(cell(page, 2, 2)).toBeVisible();
  await waitForGridMounted(page);
}

/**
 * Fills a cell through edit mode. Clicking an inactive cell focuses it
 * (Visual mode, Enter opens the editor); clicking the already-active cell
 * opens the editor directly — handle both.
 */
async function fillCell(
  page: Page,
  rowIndex: number,
  colIndex: number,
  text: string,
) {
  const input = page.locator(
    `[aria-rowindex="${rowIndex}"] > [aria-colindex="${colIndex}"] > input`,
  );

  // The grid remounts cells while columns/rows settle (LocalizedText column
  // create, language split, collection refresh). `scrollIntoViewIfNeeded`
  // throws "Element is not attached to the DOM" when its handle goes stale
  // mid-wait — retry against a fresh locator instead of failing the suite.
  const deadline = Date.now() + 15000;
  let lastError: unknown;

  while (Date.now() < deadline) {
    const target = cell(page, rowIndex, colIndex);

    try {
      await expect(target).toBeVisible({ timeout: 2000 });
      await target.scrollIntoViewIfNeeded();
      await target.click();

      if (!(await input.isVisible({ timeout: 1000 }).catch(() => false))) {
        await page.keyboard.press('Enter');
      }

      await expect(input).toBeFocused({ timeout: 2000 });
      await input.fill(text);
      await page.keyboard.press('Escape');

      return;
    } catch (err) {
      lastError = err;
      const message = err instanceof Error ? err.message : String(err);

      if (
        !message.includes('not attached') &&
        !message.includes('not stable') &&
        !message.includes('detached')
      ) {
        throw err;
      }
    }
  }

  throw lastError;
}

/** Declares the drive's language set through the chip's Edit languages dialog. */
async function declareLanguages(page: Page, tags: string[]) {
  await chips(page).first().click();
  await page.getByText('Edit languages').click();
  await inDialog(page, async (dialog, closeDialogWith) => {
    for (const tag of tags) {
      await dialog.getByPlaceholder('e.g. en or de-DE').fill(tag);
      await dialog.getByPlaceholder('e.g. en or de-DE').press('Enter');
    }

    await closeDialogWith('Save');
  });
  await waitForSaved(page);
}

/**
 * Reads the row's LocalizedText map straight from the store — the ground
 * truth for "no other language was clobbered". Finds the property by its
 * datatype, the row by its name.
 */
const localizedMapOf = (page: Page, rowName: string) =>
  page.evaluate(
    ([rowNameInner, nameProp, datatypeProp, localizedDatatype]) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const resources = Array.from(window.store.resources.values()) as any[];
      const property = resources.find(
        r => r.get?.(datatypeProp) === localizedDatatype,
      );
      const row = resources.find(r => r.get?.(nameProp) === rowNameInner);

      if (!property || !row) {
        return undefined;
      }

      return row.get(property.subject);
    },
    [rowName, NAME_PROP, DATATYPE_PROP, LOCALIZED_TEXT_DATATYPE],
  );

test.describe('LocalizedText table columns', () => {
  test.beforeEach(before);

  test('create column, edit a cell, persist as a language map', async ({
    page,
  }) => {
    test.slow();
    await createLocalizedTable(page, 'i18n basic', 'tagline');

    await fillCell(page, 2, 2, 'r1');
    await fillCell(page, 2, 3, 'Hello');

    await expect(page.getByRole('gridcell', { name: 'Hello' })).toBeVisible();

    // The header shows which language the column edits (browser default: en).
    await expect(chips(page).first()).toHaveText('en');

    await waitForSaved(page);
    await page.reload();
    await expect(page.getByRole('gridcell', { name: 'Hello' })).toBeVisible({
      timeout: 15000,
    });

    // The stored value is a language map, not a bare string.
    await expect
      .poll(() => localizedMapOf(page, 'r1'), { timeout: 15000 })
      .toEqual({ en: 'Hello' });
  });

  test('declare languages, switch, split columns, and never clobber another language', async ({
    page,
  }) => {
    test.slow();
    await createLocalizedTable(page, 'i18n full', 'tagline');

    await fillCell(page, 2, 2, 'r1');
    await fillCell(page, 2, 3, 'Hello');
    await waitForSaved(page);

    // Make the row a real collection member before manipulating columns:
    // toggling split re-renders rows from the collection query, which only
    // sees the row after the server has rebuilt its index.
    await page.reload();
    await waitForGridMounted(page);
    await expect(page.getByRole('gridcell', { name: 'r1' })).toBeVisible({
      timeout: 15000,
    });

    await declareLanguages(page, ['en', 'nl']);

    // Switch the content language to nl via the chip.
    await chips(page).first().click();
    await page.getByText('Language: nl').click();
    await expect(chips(page).first()).toHaveText('nl');

    // The en text still shows, but flagged as a missing-translation fallback.
    await expect(page.getByTitle(/No nl translation/)).toBeVisible();

    // Editing now writes nl — and must not touch en.
    await fillCell(page, 2, 3, 'Hallo');
    await expect(page.getByRole('gridcell', { name: 'Hallo' })).toBeVisible();
    await waitForSaved(page);
    await expect
      .poll(() => localizedMapOf(page, 'r1'), { timeout: 15000 })
      .toEqual({ en: 'Hello', nl: 'Hallo' });

    // Switching back resolves en again.
    await chips(page).first().click();
    await page.getByText('Language: en').click();
    await expect(page.getByRole('gridcell', { name: 'Hello' })).toBeVisible();

    // Split into one column per declared language.
    await pickFromMenu(
      chips(page).first(),
      page.getByText('Split by language'),
    );
    await expect(chips(page)).toHaveCount(2);
    await expect(chips(page).nth(0)).toHaveText('en');
    await expect(chips(page).nth(1)).toHaveText('nl');
    await expect(cell(page, 2, 3)).toContainText('Hello');
    await expect(cell(page, 2, 4)).toContainText('Hallo');

    // Type-over regression: typing directly on the en cell replaces ONLY en.
    // (This path once built the new value from scratch and wiped the map.)
    // Move activity to another cell first, so the en-cell click focuses it in
    // Visual mode instead of opening the editor on an already-active cell.
    await cell(page, 2, 2).click();
    const enCell = cell(page, 2, 3);
    await enCell.click();
    await expect(enCell).toBeFocused();
    await page.keyboard.type('Hi');
    await page.keyboard.press('Escape');
    await expect(cell(page, 2, 3)).toContainText('Hi');
    await expect(
      cell(page, 2, 4),
      'editing the en column must not remove the nl value',
    ).toContainText('Hallo');
    await waitForSaved(page);
    await expect
      .poll(() => localizedMapOf(page, 'r1'), { timeout: 15000 })
      .toEqual({ en: 'Hi', nl: 'Hallo' });

    // Clearing the nl cell removes only nl.
    const nlCell = cell(page, 2, 4);
    await nlCell.click();
    await expect(nlCell).toBeFocused();
    await page.keyboard.press('Delete');
    await expect(cell(page, 2, 4)).not.toContainText('Hallo');
    await expect(
      cell(page, 2, 3),
      'clearing the nl column must not remove the en value',
    ).toContainText('Hi');
    await waitForSaved(page);
    await expect
      .poll(() => localizedMapOf(page, 'r1'), { timeout: 15000 })
      .toEqual({ en: 'Hi' });

    // Unsplit brings back the single column with the chip's language.
    await chips(page).first().click();
    await page.getByText('Unsplit language columns').click();
    await expect(chips(page)).toHaveCount(1);
    await expect(page.getByRole('gridcell', { name: 'Hi' })).toBeVisible();

    // Both the value and the (un)split view state survive a reload.
    //
    // The barrier is the point: unsplitting writes the view's split list and
    // `save()` returns before that commit is durable, so reloading straight
    // after races it and the old, still-split view comes back from the
    // server. `pendingDirtyCount === 0` is the app's own "safe to reload"
    // signal, and it is what this line waits for.
    await waitForSaved(page);
    await page.reload();
    await expect(page.getByRole('gridcell', { name: 'Hi' })).toBeVisible({
      timeout: 15000,
    });
    await expect(chips(page)).toHaveCount(1);
  });
});
