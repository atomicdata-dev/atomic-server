import { test, expect, Locator } from '@playwright/test';
import {
  signIn,
  newDrive,
  newResource,
  before,
  currentDialog,
} from './test-utils';

test.describe('Ontology', async () => {
  test.beforeEach(before);

  test('Create and edit ontology', async ({ page }) => {
    const pickOption = async (query: Locator) => {
      await page.waitForTimeout(100);
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
    await page.getByPlaceholder('my-ontology').fill(ontologyName);
    await page.locator('dialog[open] button:has-text("Create")').click();
    await expect(page.locator(`h1:has-text("${ontologyName}")`)).toBeVisible();

    page.getByRole('button', { name: 'Edit', exact: true }).click();
    page.locator('textarea').fill('Data model for youtube thumbnail editor');
    page.getByRole('button', { name: 'Read', exact: true }).click();

    await expect(
      page.getByText('Data model for youtube thumbnail editor'),
    ).toBeVisible();

    await page.getByRole('button', { name: 'Edit', exact: true }).click();
    await page.getByRole('button', { name: 'Add class', exact: true }).click();
    await page.getByPlaceholder('shortname').fill('thumbnail');
    await page.getByRole('button', { name: 'Save' }).click();

    // Thumbnail class

    await expect(page.locator('input[value="thumbnail"]')).toBeVisible();
    await page.getByText('Change me').fill('Thumbnail of a youtube video');
    await page.getByRole('button', { name: 'add required property' }).click();
    await page
      .getByPlaceholder('Search for a property or enter a URL')
      .type('arrows');

    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Enter');

    await expect(page.locator('input[value="arrows"]')).toBeVisible();
    await expect(page.locator('input[value="a property"]')).toBeVisible();

    await page
      .locator('input[value="a property"]')
      .fill('The arrows on a thumbnail');

    // Arrows property

    await page.getByRole('button', { name: 'Configure arrows' }).click();

    await expect(currentDialog(page).getByLabel('Classtype')).toBeDisabled();

    await currentDialog(page)
      .getByLabel('Datatype')
      .selectOption('https://atomicdata.dev/datatypes/resourceArray');

    await expect(
      currentDialog(page).getByLabel('Classtype'),
    ).not.toBeDisabled();
    await currentDialog(page).getByLabel('Classtype').click();

    await currentDialog(page)
      .getByPlaceholder('Search for a class')
      .fill('arrow');

    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Enter');

    // Arrow class

    await expect(
      classCard('arrow').locator('input[value="arrow"]'),
    ).toBeVisible();
    await expect(page.locator('textarea:has-text("Change me")')).toBeVisible();
    await page.getByText('Change me').fill('An arrow in a thumbnail');

    await page
      .getByRole('button', { name: 'add recommended property' })
      .nth(1)
      .click();

    await page.getByPlaceholder('Search for a property').fill('color');
    await expect(page.getByText('The color of something')).toBeVisible();

    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Enter');

    await page
      .getByRole('button', { name: 'add required property' })
      .nth(1)
      .click();

    await page.getByPlaceholder('Search for a property').fill('arrow-kind');

    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Enter');

    await page.getByTitle('Configure arrow-kind').click();

    await expect(
      currentDialog(page).locator('input[value="arrow-kind"]'),
    ).toBeVisible();

    await currentDialog(page)
      .getByLabel('Datatype')
      .selectOption('https://atomicdata.dev/datatypes/atomicURL');

    await expect(
      currentDialog(page).getByLabel('Classtype'),
    ).not.toBeDisabled();
    await currentDialog(page).getByLabel('Classtype').click();

    await currentDialog(page)
      .getByPlaceholder('Search for a class')
      .fill('arrow-kind');

    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Enter');

    // arrow-kind class

    await expect(
      classCard('arrow-kind').locator('input[value="arrow-kind"]'),
    ).toBeVisible();

    await classCard('arrow-kind').getByTitle('add required property').click();

    await page.getByPlaceholder('Search for a property').type('name');

    await expect(
      page.getByText('name - The name of a thing or person'),
    ).toBeVisible();

    await pickOption(page.getByText('name - The name'));

    // Create arrow-kind instances

    await page.waitForTimeout(5000);

    const createInstance = async (name: string) => {
      await page.getByRole('button', { name: 'New Instance' }).click();
      await page.getByText('Search for a class').click();
      await page.getByPlaceholder('Search for a class').type('arrow-kind');

      await expect(page.getByText('arrow-kind - Change me')).toBeVisible();

      await pickOption(page.getByText('arrow-kind - Change me'));

      await expect(page.getByText('new arrow-kind')).toBeVisible();

      await expect(page.getByLabel('name')).toBeVisible();
      await page.getByLabel('name').fill(name);
      await currentDialog(page).getByRole('button', { name: 'Save' }).click();

      await expect(page.getByRole('heading', { name })).toBeVisible();
    };

    await createInstance('Red arrow with circle');
    await createInstance('Green arrow with black border');

    await page.waitForTimeout(5000);

    await page
      .getByRole('button', { name: 'add an item to the allows-only list' })
      .nth(1)
      .click();
    await page.getByRole('button', { name: 'Search for a resource' }).click();
    await page
      .getByPlaceholder('Search for a resource or ')
      .type('red arrow with circle');
    await pickOption(
      page.getByRole('dialog').getByText('Red arrow with circle'),
    );

    await page
      .getByRole('button', { name: 'add an item to the allows-only list' })
      .nth(1)
      .click();
    await page.getByRole('button', { name: 'Search for a resource' }).click();
    await page
      .getByPlaceholder('Search for a resource or ')
      .type('green arrow with black border');
    await pickOption(
      page.getByRole('dialog').getByText('Green arrow with black border'),
    );

    expect(await page.getByText('Red arrow with circle').count()).toBe(3);
    expect(await page.getByText('Green arrow with black border').count()).toBe(
      3,
    );
  });
});
