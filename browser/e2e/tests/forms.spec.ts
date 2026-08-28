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

/**
 * Creates a Form and returns its subject, landing on the builder.
 * Also provisions the data Class, results Table and Page 1.
 */
const createForm = async (page: Page, formName: string): Promise<string> => {
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

  return formSubject;
};

/**
 * Adds one field per `FIELDS` entry, waiting for each row before the next
 * click. The barrier is load-bearing: `createField` read-modify-writes the
 * page's `formFields`, so overlapping adds would drop fields.
 */
const addField = async (page: Page, label: string, key: string) => {
  await page.getByTitle('Add field').click();
  await page.getByRole('menuitem', { name: label, exact: true }).click();
  await expect(page.getByTestId(`field-row-${key}`)).toBeVisible({
    timeout: 10000,
  });
};

test.describe('forms', async () => {
  test.beforeEach(before);

  test('form dialog pre-fills name and focuses input', async ({ page }) => {
    await newResource('form', page);
    const input = page.getByPlaceholder('New Form');
    await expect(input).toHaveValue('Form');
    await expect(input).toBeFocused();
  });

  // Breadth, on its own: one field of every type, then a reload. This is
  // orthogonal to the regression walk below — it proves each type can be
  // created and rehydrated, not that a sequence of edits holds together — so
  // it runs as its own test rather than lengthening that walk. Adding all 24
  // costs ~5 resource saves each, which is most of why it is the slow half.
  test('every field type is added and survives a reload', async ({ page }) => {
    // 24 fields x ~5 resource saves each. Comfortable locally (~25s alone,
    // ~38s under load) but the long pole of this file, and CI boxes are
    // slower — keep the tripled budget. The regression walk below does not
    // need it.
    test.slow();

    const formSubject = await createForm(page, 'Every field type');

    for (const [label, key] of FIELDS) {
      await addField(page, label, key);
    }

    await waitForSync(page);
    await page.reload();
    await expect(page.getByTestId('editable-title').first()).toBeVisible({
      timeout: 15000,
    });

    for (const [, key] of FIELDS) {
      await expect(page.getByTestId(`field-row-${key}`)).toBeVisible();
    }

    expect(formSubject).toBeTruthy();
  });

  // One long walk instead of many small tests: the interesting bugs live in
  // the sequence (creation -> property sync -> rename -> delete -> reload),
  // not in any single step. Only the four field types the walk actually
  // manipulates are added — the other twenty proved nothing here that the
  // breadth test above does not, and each one cost a second of it.
  test('create a form, sync its properties, and persist across reload', async ({
    page,
  }) => {
    // --- 1. Create the Form (also provisions a data Class + Table + Page 1) ---
    const formSubject = await createForm(page, 'Contact us');

    // --- 2. Add only the fields this walk edits ---
    const WALKED: Array<[label: string, key: string]> = [
      ['Short text', 'short-text'],
      ['Number', 'number'],
      ['Radio group', 'radio'],
      ['Info box', 'info-box'],
    ];

    for (const [label, key] of WALKED) {
      await addField(page, label, key);
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
    for (const [, key] of WALKED) {
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

  /**
   * The Preview dialog runs the real `@tomic/form-renderer` over the same
   * definition a visitor gets, so it is the cheap place to prove a builder
   * setting reaches the rendered form — no publish, no second browser
   * context.
   */
  test('a multi-select respects the maximum set in the builder', async ({
    page,
  }) => {
    await createForm(page, 'Toppings');
    await addField(page, 'Multi-select', 'multi-select');

    await page.getByTestId('field-row-multi-select').click();
    await page.getByTestId('field-label-input').fill('Toppings');

    const choiceInputs = page.getByTestId('choice-option-input');
    const OPTIONS = ['Cheese', 'Olives', 'Basil'];

    for (const [index, label] of OPTIONS.entries()) {
      await page.getByRole('button', { name: 'Add option' }).click();
      await expect(choiceInputs).toHaveCount(index + 1);
      await choiceInputs.nth(index).fill(label);
    }

    await page.getByTestId('field-option-maxSelected').fill('2');

    // The option names are debounced; the preview reads the store, so wait
    // for the Tags themselves rather than for a commit to land.
    const fieldSubject = await getFieldSubjectByType(page, 'multi-select');
    await expect
      .poll(() => getOptionLabels(page, fieldSubject as string), {
        timeout: 10000,
      })
      .toEqual(OPTIONS);
    await waitForSync(page);

    await page.getByRole('button', { name: 'Preview', exact: true }).click();
    const preview = page.getByRole('dialog');
    await expect(preview.getByText('Select up to 2 options')).toBeVisible({
      timeout: 15000,
    });

    await preview.getByLabel('Cheese').check();
    await preview.getByLabel('Olives').check();
    // At the maximum the rest goes flat rather than the form growing an
    // error, and unticking one lights it back up.
    await expect(preview.getByLabel('Basil')).toBeDisabled();
    await preview.getByLabel('Olives').uncheck();
    await expect(preview.getByLabel('Basil')).toBeEnabled();
  });

  /**
   * Page-change animations, in the same Preview dialog. Asserted through
   * `animationstart` rather than by catching the modifier class mid-flight:
   * the exit phase is 180ms, far too short to poll for without flaking, but
   * the events themselves are exact — and their names say which phase played
   * and, for the exit, in which direction. The arriving page has no animation
   * of its own: its elements fade in one by one, so what proves it ran is
   * several `atomic-form-stagger-in`s, one per block.
   *
   * Which page is showing is read off the nav buttons (page 1 of two offers
   * only Next; the last page offers Back + Submit) rather than off a field
   * label — labels are debounced into the store, and this test is about the
   * transition, not about label propagation.
   */
  test('page transitions animate once switched on', async ({ page }) => {
    await createForm(page, 'Animated pages');
    // Page 1 is a radio with two options plus a heading; page 2 is one field.
    // Arriving at page 1 therefore has four things to fade in turn — the
    // question, each of its options, then the heading — which is what the
    // stagger is for, and the options are the part a block-level stagger
    // would have missed.
    await addField(page, 'Radio group', 'radio');
    const OPTIONS = ['Yes', 'No'];
    await page.getByTestId('field-row-radio').click();
    const choiceInputs = page.getByTestId('choice-option-input');

    for (const [index, label] of OPTIONS.entries()) {
      await page.getByRole('button', { name: 'Add option' }).click();
      await expect(choiceInputs).toHaveCount(index + 1);
      await choiceInputs.nth(index).fill(label);
    }

    // Option names are debounced into Tag resources; the preview builds its
    // definition from those, so wait for the Tags rather than for a commit.
    const radioSubject = await getFieldSubjectByType(page, 'radio');
    await expect
      .poll(() => getOptionLabels(page, radioSubject as string), {
        timeout: 10000,
      })
      .toEqual(OPTIONS);

    await addField(page, 'Heading', 'heading');
    await page.getByRole('button', { name: 'Add page' }).click();
    await expect(page.getByRole('button', { name: 'Page 2' })).toBeVisible({
      timeout: 10000,
    });
    // The tab appearing is not the builder having switched to it — page 2's
    // (empty) field list is. Adding a field before that lands drops it onto
    // the page being navigated away from.
    await expect(page.getByTestId('field-row-radio')).toHaveCount(0);
    await expect(page.getByTestId('field-row-heading')).toHaveCount(0);
    await waitForSync(page);
    await addField(page, 'Long text', 'long-text');
    await waitForSync(page);

    /** Records the form's own page animations as they start. Other keyframes
     * on the page (the dialog's own entrance, under a hashed
     * styled-components name) are filtered out here. */
    const recordAnimations = () =>
      page.evaluate(() => {
        const names: string[] = [];
        (window as unknown as { __formAnims: string[] }).__formAnims = names;
        document.addEventListener(
          'animationstart',
          event => {
            const name = (event as AnimationEvent).animationName;

            if (
              name.startsWith('atomic-form-page-') ||
              name === 'atomic-form-stagger-in'
            ) {
              names.push(name);
            }
          },
          true,
        );
      });

    const readAnimations = () =>
      page.evaluate(
        () => (window as unknown as { __formAnims: string[] }).__formAnims,
      );

    const openPreview = async () => {
      await page.getByRole('button', { name: 'Preview', exact: true }).click();
      const dialog = page.getByRole('dialog');
      await expect(dialog.getByRole('button', { name: 'Next' })).toBeVisible({
        timeout: 15000,
      });

      return dialog;
    };

    // A form nobody switched this on for changes pages the way it always
    // did: instantly, no animation.
    let preview = await openPreview();
    await recordAnimations();
    await preview.getByRole('button', { name: 'Next' }).click();
    await expect(preview.getByRole('button', { name: 'Submit' })).toBeVisible();
    // Longer than a full transition, so a late animation would still be seen.
    await page.waitForTimeout(600);
    expect(await readAnimations()).toEqual([]);

    // Switch it on in the builder.
    await page.keyboard.press('Escape');
    await page.getByRole('tab', { name: 'Settings' }).click();
    const toggle = page.getByLabel('Animate page transitions');
    await expect(toggle).not.toBeChecked();
    await toggle.check();
    await waitForSync(page);
    await page.getByRole('tab', { name: 'Fields' }).click();

    preview = await openPreview();
    await recordAnimations();
    // Forward leaves upward, Back leaves downward, and each arrival fades its
    // one block in. Polled rather than read once: the button that proves the
    // page swapped is on screen a frame before the arriving element's fade
    // starts. Each direction is also awaited before the next click — hitting
    // Back inside the 160ms fade cancels it, which is the right behaviour
    // (the newer intent wins) but would leave nothing to observe.
    await preview.getByRole('button', { name: 'Next' }).click();
    await expect(preview.getByRole('button', { name: 'Submit' })).toBeVisible();
    await expect
      .poll(readAnimations)
      .toEqual(['atomic-form-page-exit-up', 'atomic-form-stagger-in']);

    await preview.getByRole('button', { name: 'Back' }).click();
    await expect(preview.getByRole('button', { name: 'Next' })).toBeVisible();
    // Page 1's four things fade separately — not one event for the page, and
    // not one for the whole radio question either.
    await expect
      .poll(readAnimations)
      .toEqual([
        'atomic-form-page-exit-up',
        'atomic-form-stagger-in',
        'atomic-form-page-exit-down',
        'atomic-form-stagger-in',
        'atomic-form-stagger-in',
        'atomic-form-stagger-in',
        'atomic-form-stagger-in',
      ]);

    // …in document order, and the options take the slots after the question
    // they belong to rather than restarting from it, so the heading below
    // them lands last. Read off the inline custom property rather than a
    // computed delay: the index is static, so this says which element goes
    // when without racing the animation it drives.
    const staggerIndices = await preview
      .locator('.atomic-form-stagger')
      .evaluateAll(elements =>
        elements.map(element =>
          (element as HTMLElement).style.getPropertyValue(
            '--atomic-form-stagger-index',
          ),
        ),
      );
    expect(staggerIndices).toEqual(['0', '1', '2', '3']);

    // And those slots really do become four different delays. This is the
    // half of the cascade that lives in the stylesheet, so no unit test can
    // reach it: an earlier version capped the delay, which silently gave
    // every element past the cap the same one — the page still "animated",
    // it just stopped animating in any order. Read by putting the entering
    // class on and taking it straight back off within one evaluate, so the
    // delays are computed rather than raced.
    const readDelays = (span?: number) =>
      preview.locator('.atomic-form-blocks').evaluate((blocks, forcedSpan) => {
        blocks.classList.add('atomic-form-blocks-enter');

        if (forcedSpan !== undefined) {
          (blocks as HTMLElement).style.setProperty(
            '--atomic-form-stagger-span',
            String(forcedSpan),
          );
        }

        const computed = [...blocks.querySelectorAll('.atomic-form-stagger')]
          .map(element => getComputedStyle(element).animationDelay)
          .map(delay => Number.parseFloat(delay) * 1000);

        blocks.classList.remove('atomic-form-blocks-enter');

        return computed;
      }, span);

    const delays = await readDelays();
    expect(delays).toHaveLength(4);
    expect(delays[0]).toBe(0);

    for (const [i, delay] of delays.entries()) {
      if (i > 0) expect(delay).toBeGreaterThan(delays[i - 1]);
    }

    // A page with far more elements shortens the step instead of capping the
    // delay, so the cascade keeps its order and still opens in one wave.
    const compressed = await readDelays(100);
    expect(compressed[3]).toBeLessThan(delays[3]);

    for (const [i, delay] of compressed.entries()) {
      if (i > 0) expect(delay).toBeGreaterThan(compressed[i - 1]);
    }

    // Even switched on, a visitor who asks for reduced motion gets the page
    // change with no movement at all — and without the delay it would add.
    await page.keyboard.press('Escape');
    await page.emulateMedia({ reducedMotion: 'reduce' });
    preview = await openPreview();
    await recordAnimations();
    await preview.getByRole('button', { name: 'Next' }).click();
    await expect(preview.getByRole('button', { name: 'Submit' })).toBeVisible();
    await page.waitForTimeout(600);
    expect(await readAnimations()).toEqual([]);
    await page.emulateMedia({ reducedMotion: 'no-preference' });
  });
});
