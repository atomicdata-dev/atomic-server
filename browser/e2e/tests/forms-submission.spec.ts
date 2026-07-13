import { test, expect } from '@playwright/test';
import { before, newResource, openSubject, SERVER_URL } from './test-utils';

const FORM_TARGET_TABLE = 'https://atomicdata.dev/properties/form-target-table';
const FORM_PUBLISHED_AT = 'https://atomicdata.dev/properties/form-published-at';

/**
 * Flagship e2e for Atomic Forms (Phase 4, `planning/atomic-forms.md`): build
 * and publish a form as the owner, then — in a completely fresh,
 * unauthenticated browser context, exercising the real `/form/:id` server
 * route and the `@tomic/form-renderer` runtime it embeds, no dev-drive, no
 * `@tomic/lib` store — fill it in and submit. Finally, back as the owner,
 * confirm the submission landed as a row in the target table.
 */
test.describe('form publish and anonymous submit', () => {
  test.beforeEach(before);

  test('publish a form and submit it as an anonymous visitor', async ({
    page,
    browser,
  }) => {
    test.slow();

    // --- 1. Owner: build a two-field form ---
    await newResource('form', page);
    await page.getByPlaceholder('New Form').fill('Feedback');
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

    await page.getByTitle('Add field').click();
    await page.getByRole('menuitem', { name: 'Short text', exact: true }).click();
    await expect(page.getByTestId('field-row-short-text')).toBeVisible();

    await page.getByTestId('field-row-short-text').click();
    await page.getByTestId('field-label-input').fill('Full name');

    await page.getByTitle('Add field').click();
    await page.getByRole('menuitem', { name: 'Email', exact: true }).click();
    await expect(page.getByTestId('field-row-email')).toBeVisible();

    await page.waitForFunction(
      () => window.store.getSyncStatus().pendingDirtyCount === 0,
      undefined,
      { timeout: 15000 },
    );

    // --- 2. Publish ---
    await page.getByRole('button', { name: 'Publish', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Unpublish' })).toBeVisible();
    await page.waitForFunction(
      ({ subject, prop }) =>
        typeof window.store.resources.get(subject)?.get(prop) === 'number',
      { subject: formSubject, prop: FORM_PUBLISHED_AT },
      { timeout: 10000 },
    );
    await page.waitForFunction(
      () => window.store.getSyncStatus().pendingDirtyCount === 0,
      undefined,
      { timeout: 15000 },
    );

    const tableSubject = await page.evaluate(
      ({ subject, prop }) =>
        window.store.resources.get(subject)?.get(prop) as string | undefined,
      { subject: formSubject, prop: FORM_TARGET_TABLE },
    );
    expect(tableSubject).toBeTruthy();

    // --- 3. Fresh, unauthenticated context: open the published form and submit ---
    const visitorContext = await browser.newContext();
    const visitorPage = await visitorContext.newPage();

    await visitorPage.goto(`${SERVER_URL}/form/${formSubject}`);

    const nameInput = visitorPage.getByLabel('Full name', { exact: false });
    await expect(nameInput).toBeVisible({ timeout: 15000 });
    await nameInput.fill('Ada Lovelace');

    const emailInput = visitorPage.getByLabel('Email', { exact: false });
    await emailInput.fill('ada@example.com');

    await visitorPage.getByRole('button', { name: 'Submit', exact: true }).click();
    await expect(visitorPage.getByRole('status')).toContainText(
      'Thank you',
      { timeout: 15000 },
    );

    await visitorContext.close();

    // --- 4. Owner: the submission landed as a row in the target table ---
    await openSubject(page, tableSubject as string);
    await expect(page.getByText('Ada Lovelace')).toBeVisible({
      timeout: 15000,
    });
    await expect(page.getByText('ada@example.com')).toBeVisible();

    // --- 5. Owner: the Summary tab aggregates the submission (Phase 5b).
    // The summary is computed by the Form class extender on a forced server
    // GET when the tab opens — not synced via OPFS/WS.
    await openSubject(page, formSubject);
    await page.getByRole('tab', { name: 'Summary' }).click();
    await expect(page.getByText('1 response', { exact: true })).toBeVisible({
      timeout: 15000,
    });
    await expect(page.getByText('Ada Lovelace')).toBeVisible();

    // --- 6. Second anonymous submission only appears after Refresh
    // (extenders are not realtime — the button is the update path).
    const visitor2Context = await browser.newContext();
    const visitor2Page = await visitor2Context.newPage();
    await visitor2Page.goto(`${SERVER_URL}/form/${formSubject}`);
    const name2 = visitor2Page.getByLabel('Full name', { exact: false });
    await expect(name2).toBeVisible({ timeout: 15000 });
    await name2.fill('Grace Hopper');
    await visitor2Page
      .getByLabel('Email', { exact: false })
      .fill('grace@example.com');
    await visitor2Page
      .getByRole('button', { name: 'Submit', exact: true })
      .click();
    await expect(visitor2Page.getByRole('status')).toContainText('Thank you', {
      timeout: 15000,
    });
    await visitor2Context.close();

    await page.getByRole('button', { name: 'Refresh' }).click();
    await expect(page.getByText('2 responses', { exact: true })).toBeVisible({
      timeout: 15000,
    });
    await expect(page.getByText('Grace Hopper')).toBeVisible();
  });

  test('unpublished form shows a friendly not-available page', async ({
    page,
    browser,
  }) => {
    await newResource('form', page);
    await page.getByPlaceholder('New Form').fill('Draft form');
    await page.locator('dialog[open] button:has-text("Create")').click();
    await page.waitForURL(url => url.pathname.startsWith('/app/show'), {
      timeout: 15000,
    });
    const formSubject = await page.evaluate(() => {
      const main = document.querySelector('main[about]');

      return main?.getAttribute('about') ?? '';
    });
    expect(formSubject).toBeTruthy();

    const visitorContext = await browser.newContext();
    const visitorPage = await visitorContext.newPage();
    const response = await visitorPage.goto(`${SERVER_URL}/form/${formSubject}`);
    expect(response?.status()).toBe(410);
    await visitorContext.close();
  });
});
