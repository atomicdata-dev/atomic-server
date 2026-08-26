import { test, expect, Page } from '@playwright/test';
import { newResource, before, openSubject } from './test-utils';

const FORM_TARGET_TABLE = 'https://atomicdata.dev/properties/form-target-table';
const FORM_FIELD_TYPE = 'https://atomicdata.dev/properties/form-field-type';
const FORM_MAPS_TO = 'https://atomicdata.dev/properties/form-maps-to';
const ALLOWS_ONLY = 'https://atomicdata.dev/properties/allowsOnly';
const NAME = 'https://atomicdata.dev/properties/name';
const SHORTNAME = 'https://atomicdata.dev/properties/shortname';
const FORM_PUBLISHED_AT = 'https://atomicdata.dev/properties/form-published-at';

/** Menu label -> field-row testid key, in AddFieldMenu order. */
const FIELDS: Array<[label: string, key: string]> = [
  ['Short text', 'short-text'],
  ['Long text', 'long-text'],
  ['Email', 'email'],
  ['Phone number', 'phone'],
  ['URL', 'url'],
  ['Number', 'number'],
  ['Currency', 'currency'],
  ['Rating', 'rating'],
  ['Likert scale', 'likert'],
  ['Checkbox', 'checkbox'],
  ['Radio group', 'radio'],
  ['Dropdown', 'dropdown'],
  ['Multi-select', 'multi-select'],
  ['Dropdown multi-select', 'dropdown-multi'],
  ['Picture choice', 'picture-choice'],
  ['Date', 'date'],
  ['Date & time', 'datetime'],
  ['Choice matrix', 'choice-matrix'],
  ['Table', 'table-input'],
  ['Address', 'address'],
  ['Country', 'country'],
  ['Heading', 'heading'],
  ['Paragraph', 'paragraph'],
  ['Info box', 'info-box'],
];

// `window.store?.`, not `window.store.`: the predicate runs on every animation
// frame, including ones where a reload or navigation has replaced the document
// but the store has not attached to it yet. An unguarded read throws there, and
// a throwing predicate fails `waitForFunction` outright instead of retrying —
// turning a normal not-yet-ready frame into `Cannot read properties of
// undefined (reading 'getSyncStatus')`. Optional chaining just polls again.
const waitForSync = (page: Page) =>
  page.waitForFunction(
    () => window.store?.getSyncStatus().pendingDirtyCount === 0,
    undefined,
    { timeout: 15000 },
  );

/**
 * Debounced writes (FieldLabelInput, ChoiceOptions, PublishToggle) don't
 * touch the resource until their timer fires. Waiting on `pendingDirtyCount`
 * alone is unreliable here — the outbox routinely carries unrelated pending
 * entries from earlier steps (background page revisits, etc.), so "a commit
 * landed" doesn't mean "MY commit landed", and the true write can still be
 * queued behind others. Poll the resource's actual in-memory value instead
 * — that's the one signal that unambiguously means the debounce fired and
 * the local Loro doc has the edit — then drain the outbox so it's synced
 * before reload.
 */
const waitForPropertyValue = async (
  page: Page,
  subject: string,
  prop: string,
  expected: unknown,
) => {
  await page.waitForFunction(
    ({ subject: s, prop: p, expected: e }) => {
      const value = window.store.resources.get(s)?.get(p);

      return JSON.stringify(value) === e;
    },
    { subject, prop, expected: JSON.stringify(expected) },
    { timeout: 10000 },
  );
  await waitForSync(page);
};

/** A field row's delete button is a sibling, not a descendant, of its
 * testid'd select button — scope through the shared row wrapper. */
const fieldRowDeleteButton = (page: Page, key: string) =>
  page.getByTestId(`field-row-${key}`).locator('..').getByTitle('Delete field');

/**
 * The option labels of a choice question. Options are not stored on the field:
 * they are the Tags on its mapped Property's `allowsOnly`, so this walks
 * field -> property -> tags the way the definition builder does.
 */
const getOptionLabels = (page: Page, fieldSubject: string) =>
  page.evaluate(
    ({ subject, mapsToProp, allowsOnlyProp, nameProp }) => {
      const field = window.store.resources.get(subject);
      const property = window.store.resources.get(
        field?.get(mapsToProp) as string,
      );
      const tags = (property?.get(allowsOnlyProp) as string[]) ?? [];

      return tags.map(
        t => window.store.resources.get(t)?.get(nameProp) as string,
      );
    },
    {
      subject: fieldSubject,
      mapsToProp: FORM_MAPS_TO,
      allowsOnlyProp: ALLOWS_ONLY,
      nameProp: NAME,
    },
  );

/** Finds the subject of the (single) field of a given `form-field-type`. */
/**
 * The Property a field maps to. Form-generated Properties carry no `name` —
 * their `shortname` is both the identifier and, via `useTitle`, the results
 * table's column header (`planning/form-field-shortnames.md`).
 */
const getMappedProperty = (page: Page, fieldSubject: string) =>
  page.evaluate(
    ({ subject, prop }) =>
      window.store.resources.get(subject)?.get(prop) as string | undefined,
    { subject: fieldSubject, prop: FORM_MAPS_TO },
  );

const getFieldSubjectByType = (page: Page, type: string) =>
  page.evaluate(
    ({ fieldType, prop }) => {
      for (const r of window.store.resources.values()) {
        if (r.get(prop) === fieldType) {
          return r.subject;
        }
      }

      return undefined;
    },
    { fieldType: type, prop: FORM_FIELD_TYPE },
  );

test.describe('forms', async () => {
  test.beforeEach(before);

  test('form dialog pre-fills name and focuses input', async ({ page }) => {
    await newResource('form', page);
    const input = page.getByPlaceholder('New Form');
    await expect(input).toHaveValue('Form');
    await expect(input).toBeFocused();
  });

  // One long walk instead of many small tests: the interesting bugs live in
  // the sequence (creation -> property sync -> rename -> delete -> reload),
  // not in any single step.
  test('create a form, add every field type, and persist across reload', async ({
    page,
  }) => {
    test.slow();

    // --- 1. Create the Form (also provisions a data Class + Table + Page 1) ---
    const formName = 'Contact us';
    await newResource('form', page);
    await page.getByPlaceholder('New Form').fill(formName);
    await page.locator('dialog[open] button:has-text("Create")').click();
    await page.waitForURL(url => url.pathname.startsWith('/app/show'), {
      timeout: 15000,
    });
    await expect(page.getByTestId('editable-title').first()).toBeVisible({
      timeout: 15000,
    });

    const formSubject = await page.evaluate(() => {
      const main = document.querySelector('main[about]');

      return main?.getAttribute('about') ?? '';
    });
    expect(formSubject).toBeTruthy();

    // --- 2. Add one field of every input type + every layout type ---
    for (const [label, key] of FIELDS) {
      await page.getByTitle('Add field').click();
      await page.getByRole('menuitem', { name: label, exact: true }).click();
      await expect(page.getByTestId(`field-row-${key}`)).toBeVisible({
        timeout: 10000,
      });
    }

    await waitForSync(page);

    // --- 3. Property-sync spot checks ---
    // Rename the short-text field's label; the mapped Property's shortname
    // (and thus the Table column header) must follow.
    await page.getByTestId('field-row-short-text').click();
    const shortTextSubject = await getFieldSubjectByType(page, 'short-text');
    const shortTextProperty = (await getMappedProperty(
      page,
      shortTextSubject as string,
    )) as string;
    expect(shortTextProperty).toBeTruthy();
    const labelInput = page.getByTestId('field-label-input');
    // The Data name is read-only text until the pencil turns it into an input.
    const shortnameValue = page.getByTestId('field-shortname-value');
    await expect(labelInput).toHaveValue('Short text');
    await expect(shortnameValue).toHaveText('short-text');
    await labelInput.fill('Full name');
    await waitForPropertyValue(
      page,
      shortTextSubject as string,
      NAME,
      'Full name',
    );
    await waitForPropertyValue(page, shortTextProperty, SHORTNAME, 'full-name');
    await expect(shortnameValue).toHaveText('full-name');

    // An edited Data name is pinned: it is the identifier the answers are
    // stored under, so a later Label edit must not silently re-slug it.
    await page.getByTestId('field-shortname-edit').click();
    const shortnameInput = page.getByTestId('field-shortname-input');
    await expect(shortnameInput).toBeFocused();
    await shortnameInput.fill('visitor-name');
    // Enter commits and drops back to the read-only row (so does blur).
    await shortnameInput.press('Enter');
    await expect(shortnameInput).not.toBeVisible();
    await waitForPropertyValue(
      page,
      shortTextProperty,
      SHORTNAME,
      'visitor-name',
    );
    await labelInput.fill('Your full name');
    await waitForPropertyValue(
      page,
      shortTextSubject as string,
      NAME,
      'Your full name',
    );
    await expect(shortnameValue).toHaveText('visitor-name');

    // Delete a different field (Number) — its Property/Table column must
    // survive even though the FieldRow disappears.
    await fieldRowDeleteButton(page, 'number').click();
    await expect(page.getByTestId('field-row-number')).not.toBeVisible();
    await waitForSync(page);

    const tableSubject = await page.evaluate(
      ({ subject, prop }) =>
        window.store.resources.get(subject)?.get(prop) as string | undefined,
      { subject: formSubject, prop: FORM_TARGET_TABLE },
    );
    expect(tableSubject).toBeTruthy();

    await openSubject(page, tableSubject as string);
    // `toBeAttached`, not `toBeVisible`: one column per question means the
    // grid scrolls sideways, so a column this far right is in the DOM but
    // outside the viewport. Presence is what's under test here — the deleted
    // field's Property (and its column) must survive the delete.
    await expect(
      page.getByRole('button', { name: 'visitor-name', exact: true }),
    ).toBeAttached();
    await expect(
      page.getByRole('button', { name: 'number', exact: true }),
    ).toBeAttached();

    // Back to the Form to keep building.
    await openSubject(page, formSubject);

    // --- 4. Edit the radio field's options ---
    await page.getByTestId('field-row-radio').click();
    const radioSubject = await getFieldSubjectByType(page, 'radio');
    // Each input edits one option Tag's name in place, rather than rewriting a
    // string list — so these renames follow through to any answer already
    // submitted for them.
    // A new choice question starts with no options at all — placeholder Tags
    // would be real resources nobody asked for.
    const choiceInputs = page.getByTestId('choice-option-input');
    await expect(choiceInputs).toHaveCount(0);

    for (const [index, label] of ['A', 'B', 'C'].entries()) {
      await page.getByRole('button', { name: 'Add option' }).click();
      await expect(choiceInputs).toHaveCount(index + 1);
      await choiceInputs.nth(index).fill(label);
    }
    await expect
      .poll(() => getOptionLabels(page, radioSubject as string), {
        timeout: 10000,
      })
      .toEqual(['A', 'B', 'C']);
    await waitForSync(page);

    // --- 4b. Give the info box a style ---
    // `form-info-box-style` is the one layout-block setting that is neither
    // `name` nor `description`, so it is the one that can silently fail to
    // persist.
    await page.getByTestId('field-row-info-box').click();
    await page.getByTestId('info-box-style').selectOption('warning');
    await waitForSync(page);

    // --- 5. Publish ---
    await page.getByRole('button', { name: 'Publish', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Unpublish' })).toBeVisible();
    await page.waitForFunction(
      ({ subject, prop }) =>
        typeof window.store.resources.get(subject)?.get(prop) === 'number',
      { subject: formSubject, prop: FORM_PUBLISHED_AT },
      { timeout: 10000 },
    );
    await waitForSync(page);

    // --- 6. Reload and confirm everything persisted ---
    // NOTE: the checks below are the end-to-end regression signal for the
    // (fixed) outbox drain/sync races documented in
    // planning/outbox-drain-data-loss-race.md — drain re-entrancy, the
    // debounce window being invisible to sync status, and reload-stranded
    // cold outbox entries. Kept strict deliberately: if this flakes again,
    // suspect a regression there first.
    await page.reload();
    await expect(page.getByTestId('editable-title').first()).toBeVisible({
      timeout: 15000,
    });

    // Every field added except Number, which was deleted above.
    for (const [, key] of FIELDS) {
      if (key === 'number') {
        await expect(page.getByTestId(`field-row-${key}`)).not.toBeVisible();
      } else {
        await expect(page.getByTestId(`field-row-${key}`)).toBeVisible();
      }
    }

    await expect(page.getByTestId('field-row-short-text')).toContainText(
      'Your full name',
    );

    await page.getByTestId('field-row-info-box').click();
    await expect(page.getByTestId('info-box-style')).toHaveValue('warning');

    await page.getByTestId('field-row-radio').click();
    const reloadedChoiceInputs = page.getByTestId('choice-option-input');
    await expect(reloadedChoiceInputs).toHaveCount(3);
    await expect(reloadedChoiceInputs.nth(0)).toHaveValue('A');
    await expect(reloadedChoiceInputs.nth(1)).toHaveValue('B');
    await expect(reloadedChoiceInputs.nth(2)).toHaveValue('C');

    await expect(page.getByRole('button', { name: 'Unpublish' })).toBeVisible();

    await openSubject(page, tableSubject as string);
    await expect(
      page.getByRole('button', { name: 'visitor-name', exact: true }),
    ).toBeAttached();
    await expect(
      page.getByRole('button', { name: 'number', exact: true }),
    ).toBeAttached();
  });
});
