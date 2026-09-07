import { test, expect, type Page } from './fixtures';
import { before, editableTitle, FRONTEND_URL } from './test-utils';

/**
 * UI e2e for the table view's filtering + Views feature: the different filter
 * operators (string `starts with` / `contains`, numeric/date `>` / `<`), and
 * View persistence + isolation across reloads.
 *
 * The table, its class (name/age/birthday) and rows are all created through
 * `window.store` — the cell-fill UI is acknowledged-flaky, and the feature
 * under test is the filter/view UI, not data entry.
 */

const props = {
  name: 'https://atomicdata.dev/properties/name',
  shortname: 'https://atomicdata.dev/properties/shortname',
  description: 'https://atomicdata.dev/properties/description',
  datatype: 'https://atomicdata.dev/properties/datatype',
  recommends: 'https://atomicdata.dev/properties/recommends',
  classtype: 'https://atomicdata.dev/properties/classtype',
};

type PeopleTable = {
  table: string;
  ageProp: string;
  birthdayProp: string;
};

/**
 * Creates (via the store) a `Person` class with name(string) + age(integer) +
 * birthday(date), a Table of that class, and three rows. Navigates to the
 * table and waits for it to render. Returns the table + property subjects.
 */
async function createPeopleTable(page: Page): Promise<PeopleTable> {
  await page.waitForFunction(
    () =>
      window.store?.getClientDb()?.isReady === true &&
      window.store?.getSyncStatus().serverConnected === true,
    undefined,
    { timeout: 30000 },
  );

  const created = await page.evaluate(async p => {
    const store = window.store;
    const drive = store.getDrive();

    const makeProp = async (shortname: string, datatype: string) => {
      const r = await store.newResource({
        parent: drive,
        isA: 'https://atomicdata.dev/classes/Property',
        propVals: {
          [p.shortname]: shortname,
          [p.datatype]: datatype,
          [p.description]: `${shortname} property`,
        },
      });
      await r.save();

      return r.subject;
    };

    const ageProp = await makeProp(
      'age',
      'https://atomicdata.dev/datatypes/integer',
    );
    const birthdayProp = await makeProp(
      'birthday',
      'https://atomicdata.dev/datatypes/date',
    );

    const personClass = await store.newResource({
      parent: drive,
      isA: 'https://atomicdata.dev/classes/Class',
      propVals: {
        [p.shortname]: 'person',
        [p.description]: 'A person row',
        [p.recommends]: [p.name, ageProp, birthdayProp],
      },
    });
    await personClass.save();

    const table = await store.newResource({
      parent: drive,
      isA: 'https://atomicdata.dev/classes/Table',
      propVals: {
        [p.name]: 'People',
        [p.classtype]: personClass.subject,
      },
    });
    await table.save();

    const makeRow = async (name: string, age: number, birthday: string) => {
      const r = await store.newResource({
        parent: table.subject,
        isA: personClass.subject,
        propVals: {
          [p.name]: name,
          [ageProp]: age,
          [birthdayProp]: birthday,
        },
      });
      await r.save();
    };

    await makeRow('Alice', 30, '1994-05-12');
    await makeRow('Bob', 25, '1999-03-20');
    await makeRow('Charlie', 35, '1989-12-01');

    return { table: table.subject, ageProp, birthdayProp };
  }, props);

  await page.waitForFunction(
    () => window.store?.getSyncStatus().pendingDirtyCount === 0,
    undefined,
    { timeout: 30000 },
  );

  // A drained outbox means the commits are ACKED, not that the local index can
  // answer for them: the ClientDb writes (and the index rebuild inside each)
  // sit on a flush tick, and a filter query issued before they land silently
  // returns a short row set — the grid then shows Alice without Charlie. The
  // worker processes its messages in order, so a flush resolves only once
  // everything queued ahead of it has been written and indexed.
  await page.evaluate(() => window.store?.getClientDb()?.flush?.());

  await page.goto(
    `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(created.table)}`,
  );
  await expect(editableTitle(page)).toBeVisible({ timeout: 15000 });
  // All three rows render before we start filtering.
  await expect(page.getByRole('gridcell', { name: 'Alice' })).toBeVisible({
    timeout: 15000,
  });
  await expect(page.getByRole('gridcell', { name: 'Charlie' })).toBeVisible();

  return created;
}

/** A filter chip (in the filter toolbar) whose label starts with `prefix` —
 * scoped to the toolbar so it doesn't match the same-named column header. */
const filterChip = (page: Page, prefix: string) =>
  page
    .locator('[role="toolbar"][aria-label="Table filters"]')
    .getByRole('button', { name: new RegExp(`^${prefix}`) });

/**
 * How the chip spells each operator. Mirrors `OPERATOR_LABELS` in
 * `chunks/TablePage/tableFiltering.ts`; used to tell whether a chosen operator
 * has actually reached the chip.
 */
const OPERATOR_LABEL: Record<string, string> = {
  eq: 'is',
  gt: 'greater than',
  gte: 'at least',
  lt: 'less than',
  lte: 'at most',
  starts_with: 'starts with',
  contains: 'contains',
};

/**
 * Dismiss the filter popover once the chip reflects what was chosen.
 *
 * Pressing Escape straight after `selectOption` races the change: the popover
 * unmounts and the edit can go with it, leaving the previous operator in force
 * and the grid still showing rows the new one excludes. That surfaced as "the
 * filter does not work", ten seconds of waiting for a row to disappear that was
 * never filtered out in the first place.
 */
async function closeFilterEditor(
  page: Page,
  columnShortname: string,
  operator: string,
) {
  await expect(filterChip(page, columnShortname)).toContainText(
    OPERATOR_LABEL[operator],
  );
  await page.keyboard.press('Escape');
}

/** Adds a filter for `columnShortname` via the view-row Filter button and sets
 * its operator + value in the auto-opened chip popover. */
async function addFilter(
  page: Page,
  columnShortname: string,
  operator: string,
  value: string,
) {
  await page.getByTitle('Filter', { exact: true }).click();
  await page
    .getByRole('menuitem', { name: columnShortname, exact: true })
    .click();

  // The new chip's editor opens automatically (empty value).
  await page
    .locator('select[aria-label="Filter operator"]')
    .selectOption(operator);
  await page.getByPlaceholder('Value…').fill(value);
  await closeFilterEditor(page, columnShortname, operator);
}

test.describe('table filtering + views', () => {
  test.beforeEach(before);
  test.slow();

  test('string operators: starts_with and contains', async ({ page }) => {
    await createPeopleTable(page);

    // name starts_with "A" → only Alice.
    await addFilter(page, 'name', 'starts_with', 'A');
    await expect(page.getByRole('gridcell', { name: 'Alice' })).toBeVisible();
    await expect(page.getByRole('gridcell', { name: 'Bob' })).not.toBeVisible();
    await expect(
      page.getByRole('gridcell', { name: 'Charlie' }),
    ).not.toBeVisible();

    // Switch the same filter to contains "li" → Alice + Charlie (both contain "li").
    await filterChip(page, 'name').click();
    await page
      .locator('select[aria-label="Filter operator"]')
      .selectOption('contains');
    await page.getByPlaceholder('Value…').fill('li');
    await page.keyboard.press('Escape');

    await expect(page.getByRole('gridcell', { name: 'Alice' })).toBeVisible();
    await expect(page.getByRole('gridcell', { name: 'Charlie' })).toBeVisible();
    await expect(page.getByRole('gridcell', { name: 'Bob' })).not.toBeVisible();
  });

  test('comparison operators: numeric and date > / <', async ({ page }) => {
    await createPeopleTable(page);

    // age > 26 → Alice (30) + Charlie (35); not Bob (25).
    await addFilter(page, 'age', 'gt', '26');
    await expect(page.getByRole('gridcell', { name: 'Alice' })).toBeVisible();
    await expect(page.getByRole('gridcell', { name: 'Charlie' })).toBeVisible();
    await expect(page.getByRole('gridcell', { name: 'Bob' })).not.toBeVisible();

    // Remove the age filter, then birthday < 1995-01-01 → Alice (1994) + Charlie (1989); not Bob (1999).
    await filterChip(page, 'age').click();
    await page.getByTitle('Remove filter').click();

    await addFilter(page, 'birthday', 'lt', '1995-01-01');
    await expect(page.getByRole('gridcell', { name: 'Alice' })).toBeVisible();
    await expect(page.getByRole('gridcell', { name: 'Charlie' })).toBeVisible();
    await expect(page.getByRole('gridcell', { name: 'Bob' })).not.toBeVisible();

    // Flip the same date filter to `>` (born after 1995) → only Bob (1999).
    await filterChip(page, 'birthday').click();
    await page
      .locator('select[aria-label="Filter operator"]')
      .selectOption('gt');
    await closeFilterEditor(page, 'birthday', 'gt');
    await expect(page.getByRole('gridcell', { name: 'Bob' })).toBeVisible();
    await expect(
      page.getByRole('gridcell', { name: 'Alice' }),
    ).not.toBeVisible();
    await expect(
      page.getByRole('gridcell', { name: 'Charlie' }),
    ).not.toBeVisible();
  });

  test('views persist filters across reload and isolate them', async ({
    page,
  }) => {
    const { table } = await createPeopleTable(page);

    // Filter the (auto-created) default view: name starts_with "A" → Alice.
    await addFilter(page, 'name', 'starts_with', 'A');
    await expect(page.getByRole('gridcell', { name: 'Alice' })).toBeVisible();
    await expect(page.getByRole('gridcell', { name: 'Bob' })).not.toBeVisible();

    // The persist is debounced — wait until the default View resource actually
    // holds the filter (not just `pendingDirtyCount`, which is still 0 before
    // the debounce queues the commit), then for the commit to flush, then
    // reload. The filter must survive.
    await page.waitForFunction(
      tableSubject => {
        const store = window.store;
        const tableRes = store.resources.get(tableSubject);
        const dv = tableRes?.get?.(
          'https://atomicdata.dev/properties/table-default-view',
        ) as string | undefined;

        if (!dv) return false;

        const view = store.resources.get(dv);
        const filters = view?.get?.(
          'https://atomicdata.dev/properties/view-filters',
        );

        return Array.isArray(filters) && filters.length > 0;
      },
      table,
      { timeout: 30000 },
    );
    await page.waitForFunction(
      () => window.store?.getSyncStatus().pendingDirtyCount === 0,
      undefined,
      { timeout: 30000 },
    );
    await page.reload({ waitUntil: 'domcontentloaded' });

    await expect(page.getByRole('gridcell', { name: 'Alice' })).toBeVisible({
      timeout: 15000,
    });
    await expect(page.getByRole('gridcell', { name: 'Bob' })).not.toBeVisible();

    // Add a second view — it has its own (empty) filter set, so all three
    // rows show. This proves filters are scoped per-view, not global.
    // "Add view" is a menu now: open it, then pick the Table kind.
    await page.getByTitle('Add view').click();
    await page.getByRole('menuitem', { name: 'Table', exact: true }).click();
    await expect(page.getByRole('tab')).toHaveCount(2);
    await expect(page.getByRole('gridcell', { name: 'Bob' })).toBeVisible({
      timeout: 15000,
    });
    await expect(page.getByRole('gridcell', { name: 'Charlie' })).toBeVisible();
    await expect(page.getByRole('gridcell', { name: 'Alice' })).toBeVisible();
  });
});
