import { test, expect } from '@playwright/test';
import http from 'node:http';
import { before, newResource, openSubject, SERVER_URL } from './test-utils';

const FORM_TARGET_TABLE = 'https://atomicdata.dev/properties/form-target-table';
const FORM_PUBLISHED_AT = 'https://atomicdata.dev/properties/form-published-at';
const FORM_STYLING = 'https://atomicdata.dev/properties/form-styling';

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
    await page
      .getByRole('menuitem', { name: 'Short text', exact: true })
      .click();
    await expect(page.getByTestId('field-row-short-text')).toBeVisible();

    await page.getByTestId('field-row-short-text').click();
    await page.getByTestId('field-label-input').fill('Full name');

    await page.getByTitle('Add field').click();
    await page.getByRole('menuitem', { name: 'Email', exact: true }).click();
    await expect(page.getByTestId('field-row-email')).toBeVisible();

    // --- 1b. Theme it via the Settings tab (Phase 6 styling): custom main
    // color + round corners. These must reach the anonymous runtime through
    // the definition's `styling` object.
    await page.getByRole('tab', { name: 'Settings' }).click();
    await page.getByTitle('Pick main color').click();
    await page.getByPlaceholder('#1e43a3').fill('#e91e63');
    await page.keyboard.press('Escape');
    // The swatch label reflects the picked color once state has settled.
    await expect(page.getByTitle('Pick main color')).toContainText('#e91e63');
    await page.getByRole('button', { name: 'Round', exact: true }).click();
    await page.getByRole('tab', { name: 'Fields' }).click();

    // The color write is debounced (and flushed on tab-switch unmount);
    // wait for both keys to be in the resource before publishing. The value
    // may round-trip as a raw JSON string while the form-styling Property
    // isn't resolvable (not yet on atomicdata.dev) — accept both shapes.
    await page.waitForFunction(
      ({ subject, prop }) => {
        const raw = window.store.resources.get(subject)?.get(prop);
        const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;

        return parsed?.mainColor === '#e91e63' && parsed?.roundness === 'round';
      },
      { subject: formSubject, prop: FORM_STYLING },
      { timeout: 15000 },
    );

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

    // The Phase 6 styling applies: FormShell sets the CSS vars, so the
    // submit button renders in the custom main color with round corners.
    const submitButton = visitorPage.getByRole('button', {
      name: 'Submit',
      exact: true,
    });
    await expect(submitButton).toHaveCSS(
      'background-color',
      'rgb(233, 30, 99)',
    );
    await expect(submitButton).toHaveCSS('border-radius', '16px');

    // Phase 6 captcha: the ALTCHA widget renders above Submit and solves its
    // proof-of-work in the background (auto=onload). Submit stays disabled
    // until the widget reports `verified` (no toBeDisabled assertion — on a
    // fast machine the solve can finish before we'd check).
    await expect(visitorPage.locator('altcha-widget')).toBeVisible();

    await nameInput.fill('Ada Lovelace');

    const emailInput = visitorPage.getByLabel('Email', { exact: false });
    await emailInput.fill('ada@example.com');

    await expect(submitButton).toBeEnabled({ timeout: 30000 });
    await visitorPage
      .getByRole('button', { name: 'Submit', exact: true })
      .click();
    await expect(visitorPage.getByRole('status')).toContainText('Thank you', {
      timeout: 15000,
    });

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
    const submit2 = visitor2Page.getByRole('button', {
      name: 'Submit',
      exact: true,
    });
    await expect(submit2).toBeEnabled({ timeout: 30000 });
    await submit2.click();
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

  test('embed snippet renders chrome-less and auto-resizes in an iframe', async ({
    page,
    browser,
  }) => {
    test.slow();

    // --- 1. Owner: build and publish a minimal one-field form ---
    await newResource('form', page);
    await page.getByPlaceholder('New Form').fill('Embed test');
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
    await page
      .getByRole('menuitem', { name: 'Short text', exact: true })
      .click();
    await expect(page.getByTestId('field-row-short-text')).toBeVisible();
    await page.getByTestId('field-row-short-text').click();
    await page.getByTestId('field-label-input').fill('Full name');

    await page.waitForFunction(
      () => window.store.getSyncStatus().pendingDirtyCount === 0,
      undefined,
      { timeout: 15000 },
    );

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

    // --- 2. Owner: open the Share popover's Embed tab and read the exact
    // snippet a real user would copy-paste — this is what gets exercised
    // below, not a hand-reconstructed equivalent.
    //
    // The share slug mint (`ShareLinkPanel.tsx`) fires right after publish
    // and only retries for ~15s before giving up — shorter than how long
    // the publish commit can actually take to reach the server under
    // suite-wide load. Poll the definition endpoint directly first (a
    // generous budget, no give-up) so that by the time we open the popover
    // the form is already published server-side and the panel's own first
    // attempt succeeds immediately.
    await expect(async () => {
      const res = await page.request.get(
        `${SERVER_URL}/form/${encodeURIComponent(formSubject)}/definition`,
      );
      expect(res.ok()).toBe(true);
    }).toPass({ timeout: 60000, intervals: [1000, 2000, 3000] });

    await page.getByTitle('Share form').click({ timeout: 20000 });
    const popover = page.getByRole('dialog');
    await expect(popover).toBeVisible({ timeout: 15000 });
    await popover.getByRole('tab', { name: 'Embed' }).click();

    const snippetLocator = popover.locator('[data-code-content]');
    await expect(snippetLocator).toBeVisible({ timeout: 15000 });
    const snippet = await snippetLocator.getAttribute('data-code-content');
    expect(snippet).toBeTruthy();
    // The snippet embeds the minted share slug (same URL as the Link tab),
    // not the raw `did:ad:` subject.
    expect(snippet).toMatch(
      new RegExp(`${SERVER_URL}/form/[a-z0-9]+\\?embed=1`),
    );

    // --- 3. Fresh, unauthenticated context: load a throwaway host page
    // containing exactly that snippet, mirroring what a real embedder's
    // site would run. Served from a real local HTTP server (not
    // `page.setContent`/`about:blank`) — Chrome's `frame-ancestors *`
    // explicitly excludes non-network-scheme embedders, and its Local
    // Network Access checks block a synthetic/routed origin from framing a
    // genuine `localhost` target, so an `about:blank` host 404s in ways a
    // real embedding site never would. ---
    const hostServer = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<!doctype html><html><body>${snippet}</body></html>`);
    });
    await new Promise<void>(resolve =>
      hostServer.listen(0, '127.0.0.1', resolve),
    );
    const hostPort = (hostServer.address() as { port: number }).port;

    const visitorContext = await browser.newContext();
    const visitorPage = await visitorContext.newPage();

    try {
      await visitorPage.goto(`http://localhost:${hostPort}/`);

      const iframeLocator = visitorPage.locator('iframe');
      await expect(iframeLocator).toHaveAttribute('height', '600');

      const embedFrame = visitorPage.frameLocator('iframe');
      const nameInput = embedFrame.getByLabel('Full name', { exact: false });
      await expect(nameInput).toBeVisible({ timeout: 15000 });

      // Chrome-less: the runtime marks <html> so the full-viewport shell
      // styling is dropped (form-app/src/style.css).
      const frameHandle = await iframeLocator.elementHandle();
      const frame = await frameHandle?.contentFrame();
      await expect
        .poll(
          async () =>
            frame?.evaluate(() =>
              document.documentElement.classList.contains('atomic-form-embed'),
            ),
          { timeout: 15000 },
        )
        .toBe(true);

      // Auto-resize: the runtime's ResizeObserver reports content height via
      // postMessage, and the snippet's own listener script applies it.
      await expect
        .poll(async () => iframeLocator.evaluate(el => el.style.height), {
          timeout: 15000,
        })
        .not.toBe('');

      await nameInput.fill('Ada Lovelace');
      const embedSubmit = embedFrame.getByRole('button', {
        name: 'Submit',
        exact: true,
      });
      // Wait out the captcha's background proof-of-work solve.
      await expect(embedSubmit).toBeEnabled({ timeout: 30000 });
      await embedSubmit.click();
      await expect(embedFrame.getByRole('status')).toContainText('Thank you', {
        timeout: 15000,
      });
    } finally {
      await visitorContext.close();
      hostServer.close();
    }
  });

  test('invite-only form gates visitors on single-use invite links', async ({
    page,
    browser,
  }) => {
    test.slow();

    // --- 1. Owner: build and publish a minimal one-field form ---
    await newResource('form', page);
    await page.getByPlaceholder('New Form').fill('Private form');
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
    await page
      .getByRole('menuitem', { name: 'Short text', exact: true })
      .click();
    await expect(page.getByTestId('field-row-short-text')).toBeVisible();
    await page.getByTestId('field-row-short-text').click();
    await page.getByTestId('field-label-input').fill('Full name');

    await page.waitForFunction(
      () => window.store.getSyncStatus().pendingDirtyCount === 0,
      undefined,
      { timeout: 15000 },
    );

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

    // --- 2. Owner: switch to invite only and generate 2 invite links
    // (Settings tab → Form access section) ---
    await page.getByRole('tab', { name: 'Settings' }).click();
    await page
      .getByRole('button', { name: 'Invite only', exact: true })
      .click();

    await page.getByLabel('Number of invite links').fill('2');
    await page
      .getByRole('button', { name: 'Generate invite links', exact: true })
      .click();
    await expect(page.getByTestId('invite-code')).toHaveCount(2, {
      timeout: 15000,
    });
    const code = await page.getByTestId('invite-code').first().textContent();
    expect(code).toBeTruthy();

    await page.waitForFunction(
      () => window.store.getSyncStatus().pendingDirtyCount === 0,
      undefined,
      { timeout: 15000 },
    );

    // Wait until the server actually enforces invite-only (the form-access
    // commit and the code resources may still be in flight): the plain
    // definition must 403 while the code opens it.
    await expect(async () => {
      const bare = await page.request.get(
        `${SERVER_URL}/form/${encodeURIComponent(formSubject)}/definition`,
      );
      expect(bare.status()).toBe(403);
      const withCode = await page.request.get(
        `${SERVER_URL}/form/${encodeURIComponent(formSubject)}/definition?code=${code}`,
      );
      expect(withCode.ok()).toBe(true);
    }).toPass({ timeout: 60000, intervals: [1000, 2000, 3000] });

    // --- 3. Anonymous visitor without a code: friendly 403 page ---
    const visitorContext = await browser.newContext();
    const visitorPage = await visitorContext.newPage();
    const bareResponse = await visitorPage.goto(
      `${SERVER_URL}/form/${formSubject}`,
    );
    expect(bareResponse?.status()).toBe(403);
    await expect(visitorPage.getByText('invite-only')).toBeVisible();

    // --- 4. With the invite link: form renders and submits ---
    await visitorPage.goto(`${SERVER_URL}/form/${formSubject}?code=${code}`);
    const nameInput = visitorPage.getByLabel('Full name', { exact: false });
    await expect(nameInput).toBeVisible({ timeout: 15000 });
    await nameInput.fill('Ada Lovelace');
    const submitButton = visitorPage.getByRole('button', {
      name: 'Submit',
      exact: true,
    });
    // Wait out the captcha's background proof-of-work solve.
    await expect(submitButton).toBeEnabled({ timeout: 30000 });
    await submitButton.click();
    await expect(visitorPage.getByRole('status')).toContainText('Thank you', {
      timeout: 15000,
    });
    await visitorContext.close();

    // --- 5. The code is single-use: a second visitor with the same link
    // gets the friendly used-code page ---
    const visitor2Context = await browser.newContext();
    const visitor2Page = await visitor2Context.newPage();
    const reusedResponse = await visitor2Page.goto(
      `${SERVER_URL}/form/${formSubject}?code=${code}`,
    );
    expect(reusedResponse?.status()).toBe(403);
    await expect(visitor2Page.getByText('already been used')).toBeVisible();
    await visitor2Context.close();

    // --- 6. Owner: the consumed code shows as Used (the consumption commit
    // fans out over WS like any other, so no reload should be needed) ---
    await expect(
      page.getByTestId('invite-code').and(page.locator('[data-used="true"]')),
    ).toHaveCount(1, { timeout: 20000 });
    await expect(page.getByText('Used', { exact: true })).toBeVisible();
  });

  test('branching hides a follow-up unless its condition matches', async ({
    page,
    browser,
  }) => {
    test.slow();

    const FORM_CONDITIONS = 'https://atomicdata.dev/properties/form-conditions';

    await newResource('form', page);
    await page.getByPlaceholder('New Form').fill('Pet survey');
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
    await page
      .getByRole('menuitem', { name: 'Radio group', exact: true })
      .click();
    await expect(page.getByTestId('field-row-radio')).toBeVisible();
    await page.getByTestId('field-row-radio').click();
    await page.getByTestId('field-label-input').fill('Do you have a pet?');
    const optionInputs = page.getByTestId('choice-option-input');
    await optionInputs.nth(0).fill('Yes');
    await optionInputs.nth(1).fill('No');
    await page.waitForFunction(
      ({ typeProp, optionsProp }) => {
        for (const r of window.store.resources.values()) {
          if (r.get(typeProp) === 'radio') {
            const raw = r.get(optionsProp);
            const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;

            return parsed?.options?.[0] === 'Yes';
          }
        }

        return false;
      },
      {
        typeProp: 'https://atomicdata.dev/properties/form-field-type',
        optionsProp: 'https://atomicdata.dev/properties/form-field-options',
      },
      { timeout: 10000 },
    );

    await page.getByTitle('Add field').click();
    await page
      .getByRole('menuitem', { name: 'Short text', exact: true })
      .click();
    await expect(page.getByTestId('field-row-short-text')).toBeVisible();
    await page.getByTestId('field-row-short-text').click();
    await page.getByTestId('field-label-input').fill("Pet's name");

    // Required only applies while the field is visible — the interesting
    // branching invariant the server also enforces.
    const requiredCheckbox = page.getByRole('checkbox');
    await requiredCheckbox.check();

    await page.getByTestId('edit-conditions').click();
    await page.getByTestId('add-condition').click();
    await expect(page.getByTestId('condition-field')).toBeVisible();
    await expect(
      page.getByTestId('condition-value').locator('option[value="Yes"]'),
    ).toHaveCount(1, { timeout: 10000 });
    await page.getByTestId('condition-value').selectOption('Yes');

    const petNameSubject = await page.evaluate(
      ({ fieldType, typeProp }) => {
        for (const r of window.store.resources.values()) {
          if (r.get(typeProp) === fieldType) {
            return r.subject;
          }
        }

        return undefined;
      },
      {
        fieldType: 'short-text',
        typeProp: 'https://atomicdata.dev/properties/form-field-type',
      },
    );
    expect(petNameSubject).toBeTruthy();

    await page.waitForFunction(
      ({ subject, prop }) => {
        const conds = window.store.resources.get(subject)?.get(prop);

        return Array.isArray(conds) && conds.length > 0;
      },
      { subject: petNameSubject as string, prop: FORM_CONDITIONS },
      { timeout: 15000 },
    );
    await page.waitForFunction(
      () => window.store.getSyncStatus().pendingDirtyCount === 0,
      undefined,
      { timeout: 15000 },
    );

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

    await expect(async () => {
      const res = await page.request.get(
        `${SERVER_URL}/form/${encodeURIComponent(formSubject)}/definition`,
      );
      expect(res.ok()).toBe(true);
      const body = await res.json();
      const followUp = body.pages[0].blocks.find(
        (b: { kind: string; label?: string }) =>
          b.kind === 'field' && b.label === "Pet's name",
      );
      expect(followUp?.conditions?.[0]?.operator).toBe('equals');
      expect(followUp?.conditions?.[0]?.value).toBe('Yes');
    }).toPass({ timeout: 60000, intervals: [1000, 2000, 3000] });

    const tableSubject = await page.evaluate(
      ({ subject, prop }) =>
        window.store.resources.get(subject)?.get(prop) as string | undefined,
      { subject: formSubject, prop: FORM_TARGET_TABLE },
    );
    expect(tableSubject).toBeTruthy();

    // Visitor 1: answers No — the required follow-up stays hidden and
    // submit succeeds without it.
    const visitorContext = await browser.newContext();
    const visitorPage = await visitorContext.newPage();
    await visitorPage.goto(`${SERVER_URL}/form/${formSubject}`);
    await expect(
      visitorPage.getByText('Do you have a pet?', { exact: false }),
    ).toBeVisible({ timeout: 15000 });
    await visitorPage.getByText('No', { exact: true }).click();
    await expect(visitorPage.getByLabel("Pet's name")).toHaveCount(0);
    const submit1 = visitorPage.getByRole('button', {
      name: 'Submit',
      exact: true,
    });
    await expect(submit1).toBeEnabled({ timeout: 30000 });
    await submit1.click();
    await expect(visitorPage.getByRole('status')).toContainText('Thank you', {
      timeout: 15000,
    });
    await visitorContext.close();

    // Visitor 2: answers Yes — follow-up appears, is required, then submits.
    const visitor2Context = await browser.newContext();
    const visitor2Page = await visitor2Context.newPage();
    await visitor2Page.goto(`${SERVER_URL}/form/${formSubject}`);
    await expect(
      visitor2Page.getByText('Do you have a pet?', { exact: false }),
    ).toBeVisible({ timeout: 15000 });
    await visitor2Page.getByText('Yes', { exact: true }).click();
    const petName = visitor2Page.getByLabel("Pet's name", { exact: false });
    await expect(petName).toBeVisible();
    await petName.fill('Spot');
    const submit2 = visitor2Page.getByRole('button', {
      name: 'Submit',
      exact: true,
    });
    await expect(submit2).toBeEnabled({ timeout: 30000 });
    await submit2.click();
    await expect(visitor2Page.getByRole('status')).toContainText('Thank you', {
      timeout: 15000,
    });
    await visitor2Context.close();

    await openSubject(page, tableSubject as string);
    await expect(page.getByText('Spot')).toBeVisible({ timeout: 15000 });
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
    const response = await visitorPage.goto(
      `${SERVER_URL}/form/${formSubject}`,
    );
    expect(response?.status()).toBe(410);
    await visitorContext.close();
  });
});
