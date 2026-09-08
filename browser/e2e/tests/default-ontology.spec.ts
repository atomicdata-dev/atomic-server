import { test, expect } from './fixtures';
import { before, createTableFromDialog } from './test-utils';

test.describe('default ontology', () => {
  test.beforeEach(before);

  test('drives get a hidden "Ontology" that collects table classes', async ({
    page,
  }) => {
    // Create a table from the Issue Tracker template (name defaults to the
    // template title). Its Row class must be filed under the drive's default
    // ontology (created by `store.createDrive`) instead of under the drive.
    await createTableFromDialog(page, { template: /Issue Tracker/ });
    await expect(page.getByTestId('kanban-board')).toBeVisible();

    // The sidebar shows the table, but NOT the default ontology — it's schema
    // plumbing, hidden from the tree.
    const sidebar = page.getByRole('navigation');
    await expect(
      sidebar.getByRole('button', { name: 'Issue Tracker' }).first(),
    ).toBeVisible();
    await expect(sidebar.getByRole('button', { name: 'Ontology' })).toHaveCount(
      0,
    );

    // It stays reachable via the drive page's (collapsed) resource list.
    await page.getByTestId('sidebar-drive-open').click();
    const main = page.getByRole('main');
    await main.getByText('Resources', { exact: true }).click();
    await main.getByRole('button', { name: 'Ontology' }).click();

    // The ontology page lists the table's row class — named after what a
    // single row IS ("Issue", from the template), not a generic "row".
    await expect(
      main.getByRole('heading', { name: 'Ontology', level: 1 }),
    ).toBeVisible();
    await expect(
      main.getByRole('heading', { name: 'Issue', level: 3 }),
    ).toBeVisible();
    await expect(
      main.getByText('Represents a row in the Issue Tracker table'),
    ).toBeVisible();
    // (Listed twice: the page's own sidebar index + the properties list.)
    await expect(
      main.getByRole('link', { name: 'Status', exact: true }).first(),
    ).toBeVisible();
  });
});
