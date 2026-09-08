import { test, expect, Locator } from './fixtures';
import {
  signIn,
  newDrive,
  newResource,
  before,
  inDialog,
  DIALOG_CLOSE_BUTTON,
  SEARCHBOX_PROPERTY_PLACEHOLDER,
  waitForSearchIndex,
  waitForClassInstanceSearchable,
  waitForOntologyClass,
  smoke,
} from './test-utils';

test.describe('Ontology', async () => {
  test.beforeEach(before);

  // FLAKY (remote CI, observed once): one of the dropdown picks fails
  // to register — `pickOption` helper has a 100 ms wait that's
  // probably too short under contention. Investigate: replace the
  // `waitForTimeout(100)` in `pickOption` with an explicit visibility
  // wait on the dropdown's option list.
  test('Create and edit ontology', smoke, async ({ page }) => {
    test.slow();

    const pickOption = async (query: Locator, keyboardSteps?: number) => {
      // Wait for the dropdown option to actually render before navigating to
      // it, instead of sleeping for the open animation. `visible` doesn't
      // require in-viewport, so it holds for the keyboard path too (where the
      // option may be scrolled out of view). Search results can lag
      // `waitForSearchIndex` when the picker hits the server index.
      await query.waitFor({ state: 'visible', timeout: 30_000 });

      // Sometimes when the page moves after the dropdown opens, part of the dropdown falls outside the viewport.
      // In this case we have to use the keyboard because scrolling doesn't seem to work.
      if (keyboardSteps !== undefined) {
        for (let i = 0; i < keyboardSteps; i++) {
          await page.keyboard.press('ArrowDown');
        }

        await page.keyboard.press('Enter');

        return;
      }

      // Use the mouse if we can.
      await query.hover();
      await query.click();
    };

    const classCard = (name: string) =>
      page.getByTestId(`class-card-write-${name}`);

    // --- Test Start ---
    await signIn(page);
    await newDrive(page);

    // Create new Table
    await newResource('ontology', page);

    // Name ontology
    const ontologyName = 'youtube-thumbnail-editor';
    await inDialog(page, async (dialog, closeDialogWith) => {
      await dialog.getByPlaceholder('my-ontology').fill(ontologyName);
      await closeDialogWith('Create');
    });

    await expect(page.locator(`h1:has-text("${ontologyName}")`)).toBeVisible();

    await page
      .getByTestId('markdown-editor')
      .fill('Data model for youtube thumbnail editor');
    await page.getByRole('button', { name: 'Read', exact: true }).click();

    await expect(
      page.getByText('Data model for youtube thumbnail editor'),
    ).toBeVisible();

    // Create a thumbnail class
    await page.getByRole('button', { name: 'Edit', exact: true }).click();
    await page.getByRole('button', { name: 'Add class', exact: true }).click();

    await inDialog(page, async (dialog, closeDialogWith) => {
      await dialog.getByPlaceholder('shortname').fill('thumbnail');
      await closeDialogWith('Save');
    });

    await expect(page.locator('input[value="thumbnail"]')).toBeVisible();
    await page.getByText('Change me').fill('Thumbnail of a youtube video');
    await page.getByRole('button', { name: 'add required property' }).click();
    await page.getByPlaceholder(SEARCHBOX_PROPERTY_PLACEHOLDER).fill('arrows');

    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Enter');

    await expect(page.getByLabel('Property shortname')).toHaveValue('arrows');
    await expect(page.locator('input[value="a property"]')).toBeVisible();

    await page
      .locator('input[value="a property"]')
      .fill('The arrows on a thumbnail');

    // Arrows property
    await page.getByRole('button', { name: 'Configure arrows' }).click();

    await inDialog(page, async dialog => {
      await dialog
        .getByLabel('Datatype')
        .selectOption('https://atomicdata.dev/datatypes/resourceArray');

      await expect(dialog.getByLabel('Classtype')).not.toBeDisabled();
      await dialog.getByLabel('Classtype').click();

      await dialog.getByPlaceholder('Search for a class').fill('arrow');

      await page.keyboard.press('ArrowDown');
      await page.keyboard.press('Enter');
    });

    // Arrow class

    await expect(
      classCard('arrow').locator('input[value="arrow"]'),
    ).toBeVisible();
    await expect(page.getByText('Change me')).toBeVisible();
    await page.getByText('Change me').fill('An arrow in a thumbnail');

    await page
      .getByRole('button', { name: 'add recommended property' })
      .nth(1)
      .click();

    await expect(
      page.getByText('A textual description of something'),
    ).toBeVisible();

    await page.getByText('A textual description of something').click();

    await page
      .getByRole('button', { name: 'add required property' })
      .nth(1)
      .click();

    await page
      .getByPlaceholder(SEARCHBOX_PROPERTY_PLACEHOLDER)
      .fill('arrow-kind');

    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Enter');

    await page.getByTitle('Configure arrow-kind').click();

    await inDialog(page, async dialog => {
      await expect(dialog.locator('input[value="arrow-kind"]')).toBeVisible();

      await dialog
        .getByLabel('Datatype')
        .selectOption('https://atomicdata.dev/datatypes/atomicURL');

      await expect(dialog.getByLabel('Classtype')).not.toBeDisabled();
      await dialog.getByLabel('Classtype').click();

      await dialog.getByPlaceholder('Search for a class').fill('arrow-kind');

      await page.keyboard.press('ArrowDown');
      await page.keyboard.press('Enter');
    });

    // arrow-kind class

    const arrowKindCard = classCard('arrow-kind');
    await expect(
      arrowKindCard.locator('input[value="arrow-kind"]'),
    ).toBeVisible();

    // add name property to arrow-kind
    await arrowKindCard.getByTitle('add required property').click();

    await expect(
      page.getByText('nameThe name of a thing or person'),
    ).toBeVisible();

    await pickOption(page.getByText('nameThe name'), 1);

    // add line-type property to arrow-kind
    await arrowKindCard.getByTitle('add recommended property').click();
    await page
      .getByPlaceholder(SEARCHBOX_PROPERTY_PLACEHOLDER)
      .fill('line-type');

    await expect(page.getByText('Create line-type')).toBeVisible();

    await pickOption(page.getByText('Create line-type'));

    await page.getByTitle('Configure line-type').click();

    await inDialog(page, async (dialog, closeDialogWith) => {
      await expect(dialog.locator('input[value="line-type"]')).toBeVisible();

      await expect(
        dialog.getByRole('button', { name: 'Enum' }),
      ).not.toBeVisible();

      await dialog
        .getByLabel('Datatype')
        .selectOption('https://atomicdata.dev/datatypes/resourceArray');

      await expect(dialog.getByRole('tab', { name: 'Enum' })).toBeVisible();

      // Create two tags: dashed and solid
      await dialog.getByPlaceholder('New tag').fill('dashed');
      await dialog.getByRole('button', { name: 'Add tag' }).click();

      await expect(dialog.getByPlaceholder('New tag')).toHaveValue('');

      await expect(dialog.getByText('dashed')).toBeVisible();

      await dialog.getByPlaceholder('New tag').fill('solid');
      await dialog.getByRole('button', { name: 'Add tag' }).click();

      await expect(dialog.getByPlaceholder('New tag')).toHaveValue('');

      await expect(dialog.getByText('solid')).toBeVisible();

      await closeDialogWith(DIALOG_CLOSE_BUTTON);
    });

    // Create arrow-kind instances. The New Instance dialog lists classes
    // from the drive's ontologies — wait until Tantivy (and that filtered
    // search) can see `arrow-kind` rather than sleeping for the index flush.
    await waitForOntologyClass(page, 'arrow-kind');

    const createInstance = async (name: string) => {
      await page.getByRole('button', { name: 'New Instance' }).click();
      await inDialog(page, async (dialog, closeDialogWith) => {
        await expect(
          dialog.getByRole('heading', { name: 'Select a class' }),
        ).toBeVisible();

        await dialog.getByRole('button', { name: 'arrow-kind' }).click();

        await expect(
          dialog.getByRole('heading', { name: 'new arrow-kind' }),
        ).toBeVisible();

        await expect(dialog.getByLabel('name')).toBeVisible();
        await dialog.getByLabel('name').fill(name);
        await closeDialogWith('Save');
      });

      await expect(page.getByText('Resource loading...')).not.toBeVisible();
      await expect(page.getByRole('heading', { name, level: 2 })).toBeVisible({
        timeout: 20000,
      });
    };

    await createInstance('Red arrow with circle');
    await createInstance('Green arrow with black border');

    // The picker offers what the SERVER search returns, so wait for the exact
    // instance it is about to be asked for. A fixed sleep guesses at Tantivy's
    // commit; a count of any-old-hits is not enough either — the dialog will
    // happily come back holding "Create …" plus the other instance, and the
    // `.nth(1)` below then selects the wrong arrow.
    await waitForSearchIndex(page, 'green arrow with black border');
    // ...and the picker does not use that search. It filters by
    // `isA: arrow-kind`, and a filtered search skips the local index and waits
    // on Tantivy, so the unfiltered call above can be green while the results
    // list still holds only its "Create" row. On a loaded runner that is a 30s
    // timeout in `pickOption`; wait for the query the picker actually issues.
    await waitForClassInstanceSearchable(
      page,
      'arrow-kind',
      'red arrow with circle',
      'Red arrow with circle',
    );
    await waitForClassInstanceSearchable(
      page,
      'arrow-kind',
      'green arrow with black border',
      'Green arrow with black border',
    );

    await page
      .getByRole('button', { name: 'add an item to the allows-only list' })
      .nth(0)
      .click();
    // Adding the row opens its search directly — no second click on the
    // trigger (which the open dropdown now covers anyway).
    await page
      .getByPlaceholder('Search for a arrow-kind ')
      .fill('red arrow with circle');
    await pickOption(
      page
        .getByTestId('searchbox-results')
        .getByText('Red arrow with circle', { exact: true }),
    );

    await page
      .getByRole('button', { name: 'add an item to the allows-only list' })
      .nth(0)
      .click();
    await page
      .getByPlaceholder('Search for a arrow-kind ')
      .fill('green arrow with black border');
    // Exact match in the results list — not `.nth(1)` on the whole dialog.
    // The Create option's label contains the same words, so a substring
    // match is only the Create row until the instance hit arrives, and
    // `.nth(1)` then times out.
    await pickOption(
      page
        .getByTestId('searchbox-results')
        .getByText('Green arrow with black border', { exact: true }),
    );

    // Each instance is rendered at least three times (sidebar tree, allows-only
    // button, instances heading+link). Some race conditions add a fourth match
    // (e.g. drive-children list refresh after the commit), so accept ≥ 3.
    await expect
      .poll(() => page.getByText('Red arrow with circle').count(), {
        timeout: 15000,
      })
      .toBeGreaterThanOrEqual(3);
    await expect
      .poll(() => page.getByText('Green arrow with black border').count(), {
        timeout: 15000,
      })
      .toBeGreaterThanOrEqual(3);
  });
});
