import { test, expect } from '@playwright/test';
import {
  before,
  getCurrentSubject,
  openSubject,
  SERVER_URL,
} from './test-utils';

test.beforeEach(before);

test('form from existing table preserves columns and submits into the original table', async ({
  page,
  browser,
}) => {
  test.slow();
  const drive = await getCurrentSubject(page);
  const fixture = await page.evaluate(async parent => {
    const p = 'https://atomicdata.dev/properties/';
    const c = 'https://atomicdata.dev/classes/';
    const store = window.store;

    const make = async (
      isA: string,
      values: Record<string, string | number | string[]>,
      resourceParent = parent!,
    ) => {
      const r = await store.newResource({
        parent: resourceParent,
        isA: isA === 'SelectProperty' ? [c + 'Property', c + isA] : c + isA,
        propVals: values,
      });
      await r.save();

      return r;
    };

    const text = await make('Property', {
      [p + 'shortname']: 'full-name',
      [p + 'name']: 'Full name',
      [p + 'description']: 'A name',
      [p + 'datatype']: 'https://atomicdata.dev/datatypes/string',
    });
    const number = await make('Property', {
      [p + 'shortname']: 'age',
      [p + 'name']: 'Age',
      [p + 'description']: 'An age',
      [p + 'datatype']: 'https://atomicdata.dev/datatypes/integer',
    });
    const extra = await make('Property', {
      [p + 'shortname']: 'notes',
      [p + 'name']: 'Notes',
      [p + 'description']: 'Notes',
      [p + 'datatype']: 'https://atomicdata.dev/datatypes/string',
    });
    const tag = await make('Tag', {
      [p + 'shortname']: 'active',
      [p + 'name']: 'Active',
    });
    const select = await make('SelectProperty', {
      [p + 'shortname']: 'status',
      [p + 'name']: 'Status',
      [p + 'description']: 'A status',
      [p + 'datatype']: 'https://atomicdata.dev/datatypes/resourceArray',
      [p + 'classtype']: c + 'Tag',
      [p + 'allowsOnly']: [tag.subject],
      [p + 'max']: 1,
    });
    const rowClass = await make('Class', {
      [p + 'shortname']: 'person',
      [p + 'description']: 'A person',
      [p + 'requires']: [text.subject],
      [p + 'recommends']: [number.subject, select.subject, extra.subject],
    });
    const table = await make('Table', {
      [p + 'name']: 'People',
      [p + 'classtype']: rowClass.subject,
    });
    store.notifyResourceManuallyCreated(table);

    return {
      table: table.subject,
      text: text.subject,
      number: number.subject,
      select: select.subject,
      tag: tag.subject,
    };
  }, drive);
  await openSubject(page, fixture.table);
  await page.getByRole('button', { name: 'More', exact: true }).click();
  await page
    .getByRole('menuitem', { name: 'Create form from this table', exact: true })
    .click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Form name').fill('Register a person');
  await dialog.getByLabel('Notes', { exact: true }).uncheck();
  await dialog
    .getByRole('button', { name: 'Create form', exact: true })
    .click();
  await expect(page.getByTestId('field-row-short-text')).toBeVisible();
  const form = await getCurrentSubject(page);
  await expect(
    page.getByRole('tab', { name: 'Results', exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole('link', { name: 'Back to table', exact: true }),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Add field', exact: true }).click();
  await expect(page.getByTestId(`menu-item-${fixture.number}`)).toHaveCount(0);
  await expect(
    page.getByRole('menuitem', { name: 'Short text', exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole('menuitem', { name: 'Notes', exact: true }),
  ).toBeVisible();
  await page.keyboard.press('Escape');
  await page.getByTestId('field-row-short-text').click();
  await expect(page.getByTestId('field-shortname-edit')).toHaveCount(0);
  await expect(page.getByText('Required by the table column')).toBeVisible();
  await expect(
    page.getByRole('checkbox', { name: 'Required', exact: true }),
  ).toBeDisabled();
  const presentation = page.getByRole('combobox', { name: 'Input type' });
  await expect(presentation.locator('option')).toHaveText([
    'Short text',
    'Long text',
    'Email',
    'Phone number',
    'URL',
    'Country',
  ]);
  await presentation.selectOption('long-text');
  await expect(page.getByTestId('field-row-long-text')).toBeVisible();
  await presentation.selectOption('short-text');
  await page.getByTestId('field-label-input').fill('Your full name');
  await expect(page.getByTestId('field-row-short-text')).toContainText(
    'Your full name',
  );
  expect(
    await page.evaluate(async subject => {
      const column = await window.store.getResource(subject);

      return [
        column.get('https://atomicdata.dev/properties/name'),
        column.get('https://atomicdata.dev/properties/shortname'),
      ];
    }, fixture.text),
  ).toEqual(['Full name', 'full-name']);
  await page.getByTestId('field-row-dropdown').click();
  await expect(page.getByTestId('choice-option-input')).toHaveCount(0);
  await expect(
    page.getByRole('button', { name: 'Link options to a table' }),
  ).toHaveCount(0);
  await page.getByRole('button', { name: 'Publish', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Unpublish' })).toBeVisible();
  await expect(async () => {
    expect(
      await page.evaluate(
        async url =>
          (await fetch(url, { credentials: 'omit', cache: 'no-store' })).status,
        `${SERVER_URL}/form/${form}/definition`,
      ),
    ).toBe(200);
  }).toPass({ timeout: 60000 });
  const visitor = await browser.newContext();

  try {
    const respondent = await visitor.newPage();
    await respondent.goto(`${SERVER_URL}/form/${form}`);
    await respondent.getByLabel('Your full name').fill('Ada Lovelace');
    await respondent.getByLabel('Age').fill('36');
    await respondent.getByRole('combobox', { name: /Status/ }).click();
    await respondent
      .getByRole('option', { name: 'Active', exact: true })
      .click();
    await expect(
      respondent.getByRole('button', { name: 'Submit', exact: true }),
    ).toBeEnabled({ timeout: 30000 });
    await respondent
      .getByRole('button', { name: 'Submit', exact: true })
      .click();
    await expect(
      respondent.getByText('Thank you', { exact: false }),
    ).toBeVisible();
  } finally {
    await visitor.close();
  }

  await openSubject(page, fixture.table);
  await expect(page.getByRole('grid')).toContainText('Ada Lovelace');
  await expect(page.getByRole('grid')).toContainText('36');
  await expect(page.getByRole('grid')).toContainText('Active');
  await expect(
    page.getByRole('link', { name: 'Register a person' }),
  ).toBeVisible();
  await page.getByRole('link', { name: 'Register a person' }).click();
  await page.getByTestId('field-row-short-text').click();
  await page
    .getByRole('link', { name: 'Edit column on table', exact: true })
    .click();
  await expect(
    page.getByRole('dialog').getByRole('heading', { name: 'Edit Column' }),
  ).toBeVisible();
});
