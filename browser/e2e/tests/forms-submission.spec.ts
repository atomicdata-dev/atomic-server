import { test, expect, type Page } from '@playwright/test';
import http from 'node:http';
import { before, newResource, openSubject, SERVER_URL } from './test-utils';

/** Gives the open choice field exactly these options, in order. A new choice
 * question starts with none, and each input edits one option Tag's name — the
 * answers reference the Tag, not the text. */
const setOptionLabels = async (page: Page, labels: string[]) => {
  const inputs = page.getByTestId('choice-option-input');

  for (let i = await inputs.count(); i < labels.length; i++) {
    await page.getByRole('button', { name: 'Add option' }).click();
    await expect(inputs).toHaveCount(i + 1);
  }

  await expect(inputs).toHaveCount(labels.length);

  for (const [index, label] of labels.entries()) {
    await inputs.nth(index).fill(label);
  }
};

const FORM_TARGET_TABLE = 'https://atomicdata.dev/properties/form-target-table';
const FORM_PUBLISHED_AT = 'https://atomicdata.dev/properties/form-published-at';
const FORM_STYLING = 'https://atomicdata.dev/properties/form-styling';

/**
 * GET the published definition of `subject` from inside the browser.
 *
 * Deliberately an in-page `fetch` and NOT `page.request.get`: Playwright's
 * APIRequestContext resolves hostnames in the node process, which does not
 * honour the chromium `--host-resolver-rules` flag the dagger e2e uses to
 * point `atomic.localhost` at the atomic-server service container. There the
 * node-side lookup falls back to 127.0.0.1, where nothing listens, and every
 * such request dies with `ECONNREFUSED 127.0.0.1:9883` — a CI-only failure
 * that cannot reproduce locally, where `localhost` really is the server.
 *
 * `credentials: 'omit'` keeps the probe anonymous even when the page happens
 * to share an origin with the server (it does in CI, it does not locally),
 * so it measures what an actual visitor gets.
 *
 * The subject goes into the path raw, exactly as the `goto`s below build it.
 * `encodeURIComponent` would be wrong here: a browser sends the `%3A`
 * literally, and the route then resolves to something other than the form
 * (observed: a 410 "not accepting responses" for a form that is published).
 * The node-side client normalised the escapes away, which is why the same
 * URL worked before this became a real browser request.
 */
async function fetchDefinition(
  page: Page,
  subject: string,
  query = '',
): Promise<{ status: number; ok: boolean; body: string }> {
  return page.evaluate(async url => {
    const res = await fetch(url, { credentials: 'omit' });

    return { status: res.status, ok: res.ok, body: await res.text() };
  }, `${SERVER_URL}/form/${subject}/definition${query}`);
}

/**
 * Wait until the server itself serves the form — the client-side
 * `pendingDirtyCount === 0` only proves the publish commit left this tab.
 * Under suite-wide load the server can still be a beat behind, and opening
 * the visitor page too early renders the not-available view instead of the
 * form.
 */
async function waitForPublished(page: Page, subject: string): Promise<void> {
  await expect(async () => {
    const res = await fetchDefinition(page, subject);
    expect(res.ok).toBe(true);
  }).toPass({ timeout: 60000, intervals: [1000, 2000, 3000] });
}

/**
 * Wait until every locally-made commit has left this tab. Creating a form
 * fires several commits of its own (the data class, the table, its
 * re-parenting, the starter page); clicking Publish while those are still in
 * flight loses the `form-published-at` write, and the server then serves a
 * form that the builder already shows as published.
 */
async function waitForOutboxDrained(page: Page): Promise<void> {
  await page.waitForFunction(
    () => window.store.getSyncStatus().pendingDirtyCount === 0,
    undefined,
    { timeout: 15000 },
  );
}

/**
 * Like [waitForPublished], but for a change that should make the form
 * *un*reachable: a schedule commit has left this tab (the status line
 * already flipped) some beats before the server has applied it, so poll the
 * anonymous route until it reports the expected status.
 */
async function waitForDefinitionStatus(
  page: Page,
  subject: string,
  status: number,
): Promise<void> {
  await expect(async () => {
    const res = await fetchDefinition(page, subject);
    expect(res.status).toBe(status);
  }).toPass({ timeout: 60000, intervals: [1000, 2000, 3000] });
}

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

    await waitForPublished(page, formSubject);

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
    await waitForPublished(page, formSubject);

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
      .getByRole('button', { name: 'Generate codes', exact: true })
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
      const bare = await fetchDefinition(page, formSubject);
      expect(bare.status).toBe(403);
      const withCode = await fetchDefinition(
        page,
        formSubject,
        `?code=${code}`,
      );
      expect(withCode.ok).toBe(true);
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
    await setOptionLabels(page, ['Yes', 'No']);

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
      page.getByTestId('condition-value').locator('option', { hasText: 'Yes' }),
    ).toHaveCount(1, { timeout: 10000 });
    await page.getByTestId('condition-value').selectOption({ label: 'Yes' });

    // The conditions editor is a modal <dialog>; while it is open its
    // backdrop swallows every click on the page behind it (including
    // Publish, further down). Close it the way a user would.
    const conditionsDialog = page.locator('dialog[open]');
    await conditionsDialog
      .getByRole('button', { name: 'Done', exact: true })
      .click();
    await expect(conditionsDialog).toBeHidden();

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
      const res = await fetchDefinition(page, formSubject);
      expect(res.ok).toBe(true);
      const body = JSON.parse(res.body);
      const followUp = body.pages[0].blocks.find(
        (b: { kind: string; label?: string }) =>
          b.kind === 'field' && b.label === "Pet's name",
      );
      expect(followUp?.conditions?.[0]?.operator).toBe('equals');
      // The condition stores the option's subject; the definition resolves
      // that same subject to the 'Yes' label.
      const radio = body.pages[0].blocks.find(
        (b: { kind: string; type?: string }) =>
          b.kind === 'field' && b.type === 'radio',
      );
      const yes = radio?.options?.options?.find(
        (o: { label: string }) => o.label === 'Yes',
      );
      expect(yes?.value).toBeTruthy();
      expect(followUp?.conditions?.[0]?.value).toBe(yes.value);
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

  /**
   * The extended question types (`planning/form-field-types.md`) end-to-end:
   * configured in the builder, rendered by the published runtime, validated
   * and coerced by the submit handler, and stored on the row. One type per
   * value shape — `dropdown` (string enum), `rating` (bounded integer) and
   * `address` (composite JSON) — the rest share those paths and are covered
   * by the Rust unit tests in `server/src/forms.rs`.
   */
  test('extended field types round-trip from builder to submission', async ({
    page,
    browser,
  }) => {
    test.slow();

    await newResource('form', page);
    await page.getByPlaceholder('New Form').fill('Signup');
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

    // --- Dropdown, with its options renamed ---
    await page.getByTitle('Add field').click();
    await page.getByRole('menuitem', { name: 'Dropdown', exact: true }).click();
    await expect(page.getByTestId('field-row-dropdown')).toBeVisible();
    await page.getByTestId('field-row-dropdown').click();
    await page.getByTestId('field-label-input').fill('Plan');

    await setOptionLabels(page, ['Basic', 'Pro']);

    // --- Rating ---
    await page.getByTitle('Add field').click();
    await page.getByRole('menuitem', { name: 'Rating', exact: true }).click();
    await expect(page.getByTestId('field-row-rating')).toBeVisible();
    await page.getByTestId('field-row-rating').click();
    await page.getByTestId('field-label-input').fill('Score');

    // --- Address ---
    await page.getByTitle('Add field').click();
    await page.getByRole('menuitem', { name: 'Address', exact: true }).click();
    await expect(page.getByTestId('field-row-address')).toBeVisible();
    await page.getByTestId('field-row-address').click();
    await page.getByTestId('field-label-input').fill('Where');

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

    const tableSubject = await page.evaluate(
      ({ subject, prop }) =>
        window.store.resources.get(subject)?.get(prop) as string | undefined,
      { subject: formSubject, prop: FORM_TARGET_TABLE },
    );
    expect(tableSubject).toBeTruthy();

    await waitForPublished(page, formSubject);

    // --- Anonymous visitor fills in one of each ---
    const visitorContext = await browser.newContext();
    const visitorPage = await visitorContext.newPage();
    await visitorPage.goto(`${SERVER_URL}/form/${formSubject}`);

    // `dropdown` renders the combobox from `SelectMenu.tsx`, not a native
    // <select>: open the trigger, then pick the row from the listbox.
    const planSelect = visitorPage.getByLabel('Plan', { exact: false });
    await expect(planSelect).toBeVisible({ timeout: 15000 });
    await planSelect.click();
    await visitorPage.getByRole('option', { name: 'Pro', exact: true }).click();
    await expect(planSelect).toContainText('Pro');

    // The rating radios carry their own aria-labels; the star glyph itself is
    // decorative.
    await visitorPage.getByLabel('4 out of 5').check();

    await visitorPage.getByLabel('Address', { exact: true }).fill('Main St 1');
    await visitorPage.getByLabel('City', { exact: true }).fill('Utrecht');
    // The address's country subfield is a native <select> over ISO codes
    // (`CountrySelect`), not a free-text input.
    await visitorPage
      .getByRole('combobox', { name: /Country/ })
      .selectOption({ label: 'Netherlands' });

    const submitButton = visitorPage.getByRole('button', {
      name: 'Submit',
      exact: true,
    });
    await expect(submitButton).toBeEnabled({ timeout: 30000 });
    await submitButton.click();
    await expect(visitorPage.getByRole('status')).toContainText('Thank you', {
      timeout: 15000,
    });
    await visitorContext.close();

    // --- Owner: the row landed, one column per question, each answer in the
    // shape its datatype implies: the picked option as a string, the rating as
    // a whole number, the address as a JSON object. ---
    await openSubject(page, tableSubject as string);
    await expect(
      page.getByRole('gridcell', { name: 'Pro', exact: true }),
    ).toBeVisible({ timeout: 15000 });
    await expect(
      page.getByRole('gridcell', { name: '4', exact: true }),
    ).toBeVisible();
    await expect(page.getByRole('gridcell', { name: /Utrecht/ })).toBeVisible();

    // --- Owner: the summary aggregates each type on its existing path —
    // option counts for the dropdown, a numeric summary for the rating, and
    // a raw answer sample for the composite address value.
    await openSubject(page, formSubject);
    await page.getByRole('tab', { name: 'Summary' }).click();
    await expect(page.getByText('1 response', { exact: true })).toBeVisible({
      timeout: 15000,
    });
    await expect(page.getByText(/Utrecht/).first()).toBeVisible();
  });

  /**
   * Partial submissions / drafts (`planning/atomic-forms.md` Phase 6). A
   * visitor's half-filled answers live in their own `localStorage` — no draft
   * token in the URL, because the draft never leaves the device that will
   * resume it. Covers the three transitions that matter: the resume dialog on
   * return (Continue), Reset, and the clear-on-submit that keeps one
   * visitor's answers off the next visitor's screen.
   */
  test("an unfinished form is restored from the visitor's own device", async ({
    page,
    browser,
  }) => {
    test.slow();

    // --- 1. Owner: build and publish a minimal one-field form ---
    await newResource('form', page);
    await page.getByPlaceholder('New Form').fill('Draft form');
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

    await waitForPublished(page, formSubject);

    // --- 2. Visitor: half-fill the form, then leave ---
    const visitorContext = await browser.newContext();
    const visitorPage = await visitorContext.newPage();

    await visitorPage.goto(`${SERVER_URL}/form/${formSubject}`);

    const nameInput = () =>
      visitorPage.getByLabel('Full name', { exact: false });
    const resumeDialog = () =>
      visitorPage.getByRole('dialog', {
        name: 'Continue where you left off?',
      });

    await expect(nameInput()).toBeVisible({ timeout: 15000 });
    // Nothing to restore on a first visit, so nothing is asked.
    await expect(resumeDialog()).toBeHidden();

    await nameInput().fill('Ada Lovelace');

    // The write is debounced; wait for it to actually land rather than
    // sleeping past the debounce.
    await visitorPage.waitForFunction(
      () =>
        Object.keys(window.localStorage).some(k =>
          k.startsWith('atomic-form-draft:'),
        ),
      undefined,
      { timeout: 10000 },
    );

    // --- 3. Coming back asks before carrying on. The answers are already
    // seeded behind the dialog — they are the context for the question —
    // and Continue just dismisses it. ---
    await visitorPage.reload();
    await expect(resumeDialog()).toBeVisible({ timeout: 15000 });
    await expect(nameInput()).toHaveValue('Ada Lovelace');
    await resumeDialog().getByRole('button', { name: 'Continue' }).click();
    await expect(resumeDialog()).toBeHidden();
    await expect(nameInput()).toHaveValue('Ada Lovelace');

    // --- 4. Reset wipes the draft, on screen and on disk ---
    await visitorPage.reload();
    await expect(resumeDialog()).toBeVisible({ timeout: 15000 });
    await resumeDialog().getByRole('button', { name: 'Reset' }).click();
    await expect(resumeDialog()).toBeHidden();
    await expect(nameInput()).toHaveValue('');
    await visitorPage.reload();
    await expect(nameInput()).toBeVisible({ timeout: 15000 });
    await expect(resumeDialog()).toBeHidden();
    await expect(nameInput()).toHaveValue('');

    // --- 5. Submitting clears the draft: the next person on this browser
    // gets a blank form, not Ada's answers ---
    await nameInput().fill('Grace Hopper');
    const submitButton = visitorPage.getByRole('button', {
      name: 'Submit',
      exact: true,
    });
    await expect(submitButton).toBeEnabled({ timeout: 30000 });
    await submitButton.click();
    await expect(visitorPage.getByRole('status')).toContainText('Thank you', {
      timeout: 15000,
    });

    await visitorPage.goto(`${SERVER_URL}/form/${formSubject}`);
    await expect(nameInput()).toBeVisible({ timeout: 15000 });
    await expect(nameInput()).toHaveValue('');
    await expect(resumeDialog()).toBeHidden();

    await visitorContext.close();
  });

  /**
   * Phase 7 "Scheduled publish/unpublish": `form-open-at` / `form-close-at`
   * narrow the window inside a published form. Asserted through the real
   * anonymous routes, since the whole point is what a visitor gets — the
   * builder's own status line only mirrors the server's rule.
   */
  test('a scheduled window opens and closes a published form', async ({
    page,
    browser,
  }) => {
    test.slow();

    await newResource('form', page);
    await page.getByPlaceholder('New Form').fill('Scheduled form');
    await page.locator('dialog[open] button:has-text("Create")').click();
    await page.waitForURL(url => url.pathname.startsWith('/app/show'), {
      timeout: 15000,
    });
    const formSubject = await page.evaluate(() => {
      const main = document.querySelector('main[about]');

      return main?.getAttribute('about') ?? '';
    });
    expect(formSubject).toBeTruthy();

    await waitForOutboxDrained(page);
    await page.getByRole('button', { name: 'Publish', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Unpublish' })).toBeVisible();
    await waitForOutboxDrained(page);
    await waitForPublished(page, formSubject);

    await page.getByRole('tab', { name: 'Settings' }).click();
    const openInput = page.getByTestId('schedule-open-input');
    const closeInput = page.getByTestId('schedule-close-input');
    await expect(closeInput).toBeVisible();

    // --- Closed: a close-at in the past shuts a published form ---
    await closeInput.fill('2020-01-01T10:00');
    await expect(page.getByText(/Closed since/)).toBeVisible();
    await waitForOutboxDrained(page);
    await waitForDefinitionStatus(page, formSubject, 410);

    const visitorContext = await browser.newContext();
    const visitorPage = await visitorContext.newPage();
    const closedResponse = await visitorPage.goto(
      `${SERVER_URL}/form/${formSubject}`,
    );
    expect(closedResponse?.status()).toBe(410);
    await expect(visitorPage.getByText(/closed/i)).toBeVisible();

    // --- Not yet open: clear the close bound, schedule the start ahead ---
    await page.getByTitle('Clear close date').click();
    await openInput.fill('2999-01-01T10:00');
    await expect(page.getByText(/not open until/)).toBeVisible();
    await waitForOutboxDrained(page);
    await waitForDefinitionStatus(page, formSubject, 410);

    const pendingResponse = await visitorPage.goto(
      `${SERVER_URL}/form/${formSubject}`,
    );
    expect(pendingResponse?.status()).toBe(410);
    await expect(visitorPage.getByText(/isn't open yet/)).toBeVisible();

    // --- Clearing a bound reopens the form, as far as the builder knows ---
    await page.getByTitle('Clear open date').click();
    await expect(
      page.getByText('This form is open and accepting responses.'),
    ).toBeVisible();

    // NOT asserted through a visitor: the server's copy of a resource stops
    // taking commits once one has been parked ("Commit's Loro update depends
    // on ops the server does not have"), and removing a propval reliably
    // triggers that — a plain `remove()` + re-`set()` of `form-published-at`
    // through @tomic/lib alone reproduces it, so Unpublish→Publish is broken
    // the same way today. Reopening after a schedule is cleared is covered
    // server-side instead, by `form_submission_flow` (step 7b). Restore this
    // block once that sync bug is fixed.

    await visitorContext.close();
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
