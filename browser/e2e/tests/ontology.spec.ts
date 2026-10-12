import { test, expect, Locator } from './fixtures';
import {
  newResource,
  before,
  inDialog,
  SEARCHBOX_PROPERTY_PLACEHOLDER,
  waitForSearchIndex,
  waitForClassInstanceSearchable,
  waitForOntologyClass,
  smoke,
  getCurrentSubject,
} from './test-utils';

test.describe('Ontology', async () => {
  test.beforeEach(before);

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

    // A property line inside a class card.
    const propertyLine = (card: Locator, shortname: string) =>
      card
        .locator('li')
        .filter({ has: page.locator(`input[value="${shortname}"]`) });

    // Changing the datatype swaps in a new property (the datatype is part of
    // its ID), which replaces the line. Wait for the replacement before using
    // the line, or what was opened on the old one closes again.
    const setDatatype = async (line: Locator, datatype: string) => {
      await line.getByLabel('Property datatype').selectOption(datatype);
      await expect(line.getByLabel('Property datatype')).toHaveValue(datatype);
    };

    // Sets the class a property links to, in the class's constraints.
    const setLinkedClass = async (line: Locator, className: string) => {
      await line.getByText('Constraints').click();
      await expect(line.getByLabel('Linked class')).not.toBeDisabled();
      await line.getByLabel('Linked class').click();
      await page.getByPlaceholder('Search for a class').fill(className);
      await page.keyboard.press('ArrowDown');
      await page.keyboard.press('Enter');
    };

    // --- Test Start ---

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

    // Arrows property: a list of arrows. The datatype belongs to the
    // property; the class it links to is a constraint of the thumbnail class.
    const arrowsLine = propertyLine(classCard('thumbnail'), 'arrows');
    await arrowsLine
      .getByLabel('Property datatype')
      .selectOption('https://atomicdata.dev/datatypes/resourceArray');
    // The datatype is part of the property's ID: the line is replaced by one
    // for the new property. Opening Constraints before that remounts it shut.
    await expect(arrowsLine.getByLabel('Property datatype')).toHaveValue(
      'https://atomicdata.dev/datatypes/resourceArray',
    );
    await setLinkedClass(arrowsLine, 'arrow');

    // Arrow class

    await expect(
      classCard('arrow').locator('input[value="arrow"]'),
    ).toBeVisible();
    const arrowDescription = classCard('arrow').getByText('Change me');

    await expect(arrowDescription).toBeVisible();
    await arrowDescription.fill('An arrow in a thumbnail');

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

    const arrowKindLine = propertyLine(classCard('thumbnail'), 'arrow-kind');
    await setDatatype(
      arrowKindLine,
      'https://atomicdata.dev/datatypes/atomicURL',
    );
    await setLinkedClass(arrowKindLine, 'arrow-kind');

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

    // The options of a property are a constraint of the class that uses it.
    const lineTypeLine = propertyLine(arrowKindCard, 'line-type');
    await setDatatype(
      lineTypeLine,
      'https://atomicdata.dev/datatypes/resourceArray',
    );
    await lineTypeLine.getByText('Constraints').click();

    // Create two tags: dashed and solid
    await lineTypeLine.getByPlaceholder('New tag').fill('dashed');
    await lineTypeLine.getByRole('button', { name: 'Add tag' }).click();
    await expect(lineTypeLine.getByPlaceholder('New tag')).toHaveValue('');
    await expect(lineTypeLine.getByText('dashed')).toBeVisible();

    await lineTypeLine.getByPlaceholder('New tag').fill('solid');
    await lineTypeLine.getByRole('button', { name: 'Add tag' }).click();
    await expect(lineTypeLine.getByPlaceholder('New tag')).toHaveValue('');
    await expect(lineTypeLine.getByText('solid')).toBeVisible();

    // Create arrow-kind instances. The New Instance dialog lists classes
    // from the drive's ontologies — wait until Tantivy (and that filtered
    // search) can see `arrow-kind` rather than sleeping for the index flush.
    await waitForOntologyClass(page, 'arrow-kind');

    // Hold the first save's completion after persistence. Its card can render
    // and the next form can open while the old onSuccess callback is pending.
    await page.evaluate(
      async subject => {
        const ontology = await window.store.getResource(subject!);
        const save = ontology.save.bind(ontology);
        const state = window as unknown as {
          finishPreviousInstanceSave: () => void;
          previousInstanceSaveHeld: boolean;
        };
        const gate = new Promise<void>(resolve => {
          state.finishPreviousInstanceSave = resolve;
        });

        ontology.save = async (...args) => {
          const result = await save(...args);
          ontology.save = save;
          state.previousInstanceSaveHeld = true;
          await gate;

          return result;
        };
      },
      await getCurrentSubject(page),
    );

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

        if (name === 'Green arrow with black border') {
          await page.evaluate(async () => {
            (
              window as unknown as { finishPreviousInstanceSave: () => void }
            ).finishPreviousInstanceSave();
            // Allow the older save's scroll callback and React update to run.
            await new Promise<void>(resolve =>
              requestAnimationFrame(() =>
                requestAnimationFrame(() => resolve()),
              ),
            );
          });
          await expect(dialog.getByLabel('name')).toHaveValue(name);
        }

        await closeDialogWith('Save');
      });

      if (name === 'Red arrow with circle') return;
      await expect(page.getByText('Resource loading...')).not.toBeVisible();
      await expect(page.getByRole('heading', { name, level: 2 })).toBeVisible({
        timeout: 20000,
      });
    };

    await createInstance('Red arrow with circle');
    await page.waitForFunction(
      () =>
        (window as unknown as { previousInstanceSaveHeld: boolean })
          .previousInstanceSaveHeld,
    );
    await createInstance('Green arrow with black border');
    await expect(
      page.getByRole('heading', { name: 'Red arrow with circle', level: 2 }),
    ).toBeVisible();

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

    await arrowKindLine
      .getByRole('button', { name: 'add an item to the allows-only list' })
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

    await arrowKindLine
      .getByRole('button', { name: 'add an item to the allows-only list' })
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
