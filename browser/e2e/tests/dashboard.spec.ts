import { test, expect, type Page } from './fixtures';
import {
  before,
  editableTitle,
  FRONTEND_URL,
  newResource,
  pickFromMenu,
  waitForRowsMaterialized,
  waitForSynced,
  smoke,
} from './test-utils';

/**
 * A dashboard is stored configuration and nothing else, so what is worth proving
 * end to end is that the configuration arrives wired up: a number computed by the
 * store, a chart bucketed by a column, an embedded editable table — and that a
 * person can change any of it, since the assistant writes the same resources.
 *
 * The table and its rows are built through `window.store`: the feature under test
 * is the dashboard, not cell entry.
 */

const props = {
  name: 'https://atomicdata.dev/properties/name',
  shortname: 'https://atomicdata.dev/properties/shortname',
  description: 'https://atomicdata.dev/properties/description',
  datatype: 'https://atomicdata.dev/properties/datatype',
  recommends: 'https://atomicdata.dev/properties/recommends',
  classtype: 'https://atomicdata.dev/properties/classtype',
  allowsOnly: 'https://atomicdata.dev/properties/allowsOnly',
};

type Fixture = { table: string; amount: string; category: string };

/**
 * A Spending table with an `amount` (float) and a `category` (select) column and
 * four rows. `category` is a select rather than free text because that is what
 * the breakdown menu offers to group by.
 */
async function createSpendingTable(page: Page): Promise<Fixture> {
  await page.waitForFunction(
    () =>
      window.store?.getClientDb()?.isReady === true &&
      window.store?.getSyncStatus().serverConnected === true,
    undefined,
    { timeout: 30_000 },
  );

  const created = await page.evaluate(async p => {
    const store = window.store;
    const drive = store.getDrive();

    const amount = await store.newResource({
      parent: drive,
      isA: 'https://atomicdata.dev/classes/Property',
      propVals: {
        [p.shortname]: 'amount',
        [p.datatype]: 'https://atomicdata.dev/datatypes/float',
        [p.description]: 'What it cost',
      },
    });
    await amount.save();

    const tag = async (name: string) => {
      const t = await store.newResource({
        parent: drive,
        isA: 'https://atomicdata.dev/classes/Tag',
        propVals: { [p.shortname]: name },
      });
      await t.save();

      return t.subject;
    };

    const food = await tag('food');
    const transport = await tag('transport');
    const tools = await tag('tools');

    const category = await store.newResource({
      parent: drive,
      isA: 'https://atomicdata.dev/classes/Property',
      propVals: {
        [p.shortname]: 'category',
        [p.datatype]: 'https://atomicdata.dev/datatypes/resourceArray',
        [p.description]: 'What kind of spend',
        [p.allowsOnly]: [food, transport, tools],
      },
    });
    await category.save();

    const cls = await store.newResource({
      parent: drive,
      isA: 'https://atomicdata.dev/classes/Class',
      propVals: {
        [p.shortname]: 'expense',
        [p.description]: 'An expense',
        [p.recommends]: [p.name, amount.subject, category.subject],
      },
    });
    await cls.save();

    const table = await store.newResource({
      parent: drive,
      isA: 'https://atomicdata.dev/classes/Table',
      propVals: { [p.name]: 'Spending', [p.classtype]: cls.subject },
    });
    await table.save();

    const rows: [string, number, string][] = [
      ['Coffee', 4.5, food],
      ['Lunch', 12, food],
      ['Train', 30, transport],
      ['Laptop', 900, tools],
    ];

    for (const [name, value, cat] of rows) {
      const row = await store.newResource({
        parent: table.subject,
        isA: cls.subject,
        propVals: {
          [p.name]: name,
          [amount.subject]: value,
          [category.subject]: [cat],
        },
      });
      await row.save();
    }

    return {
      table: table.subject,
      amount: amount.subject,
      category: category.subject,
    };
  }, props);

  await waitForRowsMaterialized(page, 30_000);

  return created;
}

/** Creates a dashboard with the four block kinds and opens it. */
async function createDashboard(page: Page, fixture: Fixture): Promise<string> {
  const subject = await page.evaluate(async f => {
    const store = window.store;
    const NAME = 'https://atomicdata.dev/properties/name';
    const DESC = 'https://atomicdata.dev/properties/description';
    const D = {
      dashboard: 'https://atomicdata.dev/classes/Dashboard',
      block: 'https://atomicdata.dev/classes/Block',
      blocks: 'https://atomicdata.dev/properties/dashboard-blocks',
      layout: 'https://atomicdata.dev/properties/dashboard-layout',
      kind: 'https://atomicdata.dev/properties/block-kind',
      quickAdd: 'https://atomicdata.dev/properties/block-quick-add',
      source: 'https://atomicdata.dev/properties/block-source',
      aggregate: 'https://atomicdata.dev/properties/block-aggregate',
      chart: 'https://atomicdata.dev/properties/block-chart-spec',
    };

    const dashboard = await store.newResource({
      parent: store.getDrive(),
      isA: D.dashboard,
      propVals: { [NAME]: 'Spending overview' },
    });
    await dashboard.save();

    const block = async (propVals: Record<string, unknown>) => {
      const b = await store.newResource({
        parent: dashboard.subject,
        isA: D.block,
        propVals: propVals as never,
      });
      await b.save();

      return b.subject;
    };

    const total = await block({
      [NAME]: 'Total spent',
      [D.kind]: 'stat',
      [D.source]: f.table,
      [D.aggregate]: { function: 'sum', property: f.amount },
    });
    const count = await block({
      [NAME]: 'Expenses',
      [D.kind]: 'stat',
      [D.source]: f.table,
      [D.aggregate]: { function: 'count' },
    });
    const chart = await block({
      [NAME]: 'Per category',
      [D.kind]: 'chart',
      [D.source]: f.table,
      [D.aggregate]: { function: 'sum', property: f.amount },
      [D.chart]: { mark: 'bar', field: f.category, granularity: 'exact' },
    });
    const note = await block({
      [NAME]: 'Notes',
      [D.kind]: 'text',
      [DESC]: 'Watch the **tools** budget',
    });
    const list = await block({
      [NAME]: 'All expenses',
      [D.kind]: 'view',
      [D.source]: f.table,
    });
    const add = await block({
      [NAME]: 'Quick add',
      [D.kind]: 'create',
      [D.source]: f.table,
      [D.quickAdd]: {
        label: 'Add expense',
        field: 'https://atomicdata.dev/properties/name',
        placeholder: 'What did you buy?',
      },
    });

    await dashboard.set(
      D.blocks,
      [total, count, chart, note, list, add],
      false,
    );
    // Written with the legacy `x`/`y` keys on purpose: dashboards created before
    // the layout became size-only still carry them, and their sizes must survive.
    await dashboard.set(
      D.layout,
      [
        { subject: total, x: 0, y: 0, w: 3, h: 1 },
        { subject: count, x: 3, y: 0, w: 3, h: 1 },
        { subject: chart, x: 6, y: 0, w: 6, h: 2 },
        { subject: note, x: 0, y: 1, w: 6, h: 1 },
        { subject: list, x: 0, y: 2, w: 12, h: 3 },
        { subject: add, x: 0, y: 5, w: 4, h: 1 },
      ] as never,
      false,
    );
    await dashboard.save();

    return dashboard.subject;
  }, fixture);

  await waitForRowsMaterialized(page, 30_000);
  await page.goto(
    `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(subject)}`,
  );
  await expect(editableTitle(page)).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId('dashboard-grid')).toBeVisible({
    timeout: 15_000,
  });
  await page.waitForFunction(
    () => window.store?.getClientDb()?.isReady === true,
    undefined,
    { timeout: 30_000 },
  );

  return subject;
}

/**
 * The block card whose heading is exactly `title` — matched on the heading rather
 * than on any text, so "Expenses" doesn't also match "All expenses".
 */
const block = (page: Page, title: string) =>
  page
    .getByTestId('dashboard-block')
    .filter({ has: page.getByRole('heading', { name: title, exact: true }) });

/**
 * Picks a table in the config dialog's resource searchbox. The trigger is a
 * button; the text field only exists once its popover is open.
 */
async function pickTable(page: Page, name: string) {
  await page.locator('#block-source').click();
  // The popover's field takes focus on open, so type into it rather than
  // locating it — it is portaled out of the dialog and has no stable hook.
  await page.keyboard.type(name);
  await page
    .getByTestId('searchbox-results')
    .getByText(name, { exact: true })
    .first()
    .click();
}

test.describe('dashboards', () => {
  test.beforeEach(before);
  test.slow();

  test('a dashboard is created by name, not by writing JSON', async ({
    page,
  }) => {
    // Without a create dialog this class fell through to the generic resource
    // form, which renders `dashboard-blocks` and `dashboard-layout` as raw JSON
    // fields — asking for a layout before any blocks exist to lay out.
    await newResource('dashboard', page);
    await page.getByTestId('new-dashboard-name').fill('Overview');
    await page.getByTestId('new-dashboard-create').click();

    await expect(
      page.getByRole('textbox', { name: 'Set a title' }),
    ).toHaveValue('Overview', {
      timeout: 15_000,
    });

    // It lands on the dashboard's own editor, which is where blocks are added.
    await expect(page.getByTitle('Add block')).toBeVisible();
    await expect(page.getByText(/Nothing here yet/)).toBeVisible();

    await page.getByTitle('Add block').click();
    await expect(page.getByRole('menuitem', { name: 'Number' })).toBeVisible();
    await expect(page.getByRole('menuitem', { name: 'Button' })).toBeVisible();
  });

  test(
    'the four block kinds each show what they were configured to',
    smoke,
    async ({ page }) => {
      const fixture = await createSpendingTable(page);
      await createDashboard(page, fixture);

      // The store computes the number over every matching row, so it is the real
      // total rather than a sum of whatever page happened to load.
      await expect(block(page, 'Total spent')).toContainText('946.5', {
        timeout: 15_000,
      });
      await expect(block(page, 'Expenses')).toContainText('4', {
        timeout: 15_000,
      });

      // One bar per category, largest first, each labelled by its tag name.
      const chart = block(page, 'Per category');
      await expect(chart).toContainText('900');
      await expect(chart).toContainText('30');
      // 4.5 + 12 — the two food rows, bucketed together.
      await expect(chart).toContainText('16.5');

      // Markdown, not the raw asterisks.
      await expect(block(page, 'Notes')).toContainText(
        'Watch the tools budget',
      );

      // The view block is the real grid: its rows are there and editable.
      const list = block(page, 'All expenses');
      await expect(
        list.getByRole('gridcell', { name: 'Laptop' }),
      ).toBeVisible();
      await expect(list.getByRole('grid')).toBeVisible();
    },
  );

  test('a button block adds a row, and the numbers beside it follow', async ({
    page,
  }) => {
    const fixture = await createSpendingTable(page);
    await createDashboard(page, fixture);

    await expect(block(page, 'Expenses')).toContainText('4', {
      timeout: 15_000,
    });

    // The whole point of a dashboard as an app shell: press the thing, and the
    // page you are already looking at updates.
    const bar = block(page, 'Quick add');
    await expect(bar.getByTestId('quick-add-input')).toHaveAttribute(
      'placeholder',
      'What did you buy?',
    );
    await bar.getByTestId('quick-add-input').fill('Notebook');
    await bar.getByTestId('quick-add-button').click();

    // Count goes 4 → 5 without a reload: the row's save is what the numbers
    // re-read on.
    await expect(block(page, 'Expenses')).toContainText('5', {
      timeout: 15_000,
    });

    // The row is really there — but only after a reload in the embedded table
    // beside it. That grid freezes its member count at first load and treats
    // anything past it as a session draft, and a create block has no way to bump
    // another block's count. The numbers update live; a listed row does not.
    await page.waitForFunction(
      () => window.store?.getSyncStatus().pendingDirtyCount === 0,
      undefined,
      { timeout: 15_000 },
    );
    await page.reload({ waitUntil: 'domcontentloaded' });
    await expect(
      block(page, 'All expenses').getByRole('gridcell', { name: 'Notebook' }),
    ).toBeVisible({ timeout: 15_000 });
  });

  test('a stored width reaches the grid, and survives a reload', async ({
    page,
  }) => {
    const fixture = await createSpendingTable(page);
    await createDashboard(page, fixture);

    const total = block(page, 'Total spent');
    await expect(total).toContainText('946.5', { timeout: 15_000 });

    // `grid-column: span N` resolves into `gridColumnStart`, not End.
    const spanOf = () =>
      total.evaluate(el => getComputedStyle(el).gridColumnStart);

    // The fixture stores w: 3 for this block.
    expect(await spanOf()).toBe('span 3');

    await pickFromMenu(
      total.getByTitle('Block options'),
      page.getByRole('menuitem', { name: /Full width/ }),
    );
    await page.keyboard.press('Escape');

    // Stored layout has to actually reach the grid — it was written and read by
    // nothing at first, so the menu appeared to do nothing.
    await expect.poll(spanOf, { timeout: 15_000 }).toBe('span 12');

    await page.waitForFunction(
      () => window.store?.getSyncStatus().pendingDirtyCount === 0,
      undefined,
      { timeout: 15_000 },
    );
    await page.reload({ waitUntil: 'domcontentloaded' });
    await expect(block(page, 'Total spent')).toContainText('946.5', {
      timeout: 15_000,
    });
    await expect.poll(spanOf, { timeout: 15_000 }).toBe('span 12');
  });

  test('a person can reconfigure a block, and it survives a reload', async ({
    page,
  }) => {
    const fixture = await createSpendingTable(page);
    await createDashboard(page, fixture);
    await expect(block(page, 'Total spent')).toContainText('946.5', {
      timeout: 15_000,
    });

    // Everything the create tool can write, the dialog can change — otherwise
    // the assistant builds dashboards their owner cannot edit.
    await pickFromMenu(
      block(page, 'Total spent').getByTitle('Block options'),
      page.getByRole('menuitem', { name: 'Configure' }),
    );

    await page.getByTestId('block-name').fill('Average spend');
    await page.getByTestId('block-function').selectOption('avg');
    await page.getByTestId('block-target').selectOption({ label: 'amount' });
    await page.getByTestId('block-save').click();
    await expect(page.getByTestId('block-save')).not.toBeVisible();

    // 946.5 over four rows.
    await expect(block(page, 'Average spend')).toContainText('236.63', {
      timeout: 15_000,
    });

    await waitForSynced(page);

    await page.reload({ waitUntil: 'domcontentloaded' });

    await expect(block(page, 'Average spend')).toContainText('236.63', {
      timeout: 15_000,
    });
  });

  test('a measure cannot be saved with nothing to measure', async ({
    page,
  }) => {
    const fixture = await createSpendingTable(page);
    await createDashboard(page, fixture);
    await expect(block(page, 'Total spent')).toContainText('946.5', {
      timeout: 15_000,
    });

    await pickFromMenu(
      block(page, 'Total spent').getByTitle('Block options'),
      page.getByRole('menuitem', { name: 'Configure' }),
    );

    // Clearing the column leaves "sum of nothing", which used to save happily
    // and render as an em-dash forever.
    await page.getByTestId('block-target').selectOption('');
    await expect(page.getByTestId('block-save')).toBeDisabled();

    // Count needs no column, so it is saveable immediately.
    await page.getByTestId('block-function').selectOption('count');
    await expect(page.getByTestId('block-save')).toBeEnabled();
    await page.getByTestId('block-save').click();

    await expect(block(page, 'Total spent')).toContainText('4', {
      timeout: 15_000,
    });
  });

  test('a block added from the menu can be configured into a working number', async ({
    page,
  }) => {
    const fixture = await createSpendingTable(page);
    await createDashboard(page, fixture);
    await expect(page.getByTestId('dashboard-block')).toHaveCount(6, {
      timeout: 15_000,
    });

    await pickFromMenu(
      page.getByTitle('Add block'),
      page.getByRole('menuitem', { name: 'Number' }),
    );

    // Adding a block opens its config dialog: a block that arrives empty and
    // silent is worse than one that asks what it should show.
    await page.getByTestId('block-name').fill('Biggest expense');
    await pickTable(page, 'Spending');
    await page.getByTestId('block-function').selectOption('max');
    await page.getByTestId('block-target').selectOption({ label: 'amount' });
    await page.getByTestId('block-save').click();

    await expect(block(page, 'Biggest expense')).toContainText('900', {
      timeout: 15_000,
    });
    await expect(page.getByTestId('dashboard-block')).toHaveCount(7);
  });
});
