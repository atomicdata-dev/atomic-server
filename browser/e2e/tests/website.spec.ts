import { test, expect } from '@playwright/test';
import { createFromCatalog, before, waitForSynced } from './test-utils';
import {
  enableAIForTesting,
  sendChatMessage,
  setupScriptedToolCallMocks,
} from './ai-mock';

/** A private document stays editable; an exported release keeps its old text. */
test('website document preview, frozen release and reload', async ({
  page,
}) => {
  // Measured over sixteen four-worker rounds, this test runs 43797 to 57261 ms,
  // and the second of those is 95% of the 60s default. It creates a document and
  // a website, freezes a release, downloads the zip, edits the document again and
  // reloads, and the wait added below is part of that cost. A wall failure names
  // the wall rather than the step that was late, so the test would start blaming
  // whichever preview assertion happened to be in flight. `test.slow()` is what
  // the other test in this file already carries for the same reason.
  test.slow();
  await before({ page });
  await page
    .getByRole('button', { name: 'New Document', exact: true })
    .first()
    .click();
  await page.locator('#document-editor').waitFor();
  await page
    .locator('#document-editor')
    .fill('This is the first published garden note.');
  await createFromCatalog(page, 'Website');
  await page.getByRole('button', { name: 'More', exact: true }).click();
  const prepare = page.getByTestId('menu-item-website-prepare');
  await expect(prepare).toBeEnabled({ timeout: 30000 });
  const websiteURL = page.url();
  const preview = page.frameLocator('iframe[title="Website preview"]');
  await expect(
    preview.getByText('This is the first published garden note.'),
  ).toBeVisible();
  await prepare.click();
  await page
    .getByRole('button', { name: 'Create release', exact: true })
    .click();
  await expect(page.getByText('Frozen release', { exact: true })).toBeVisible();
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    websiteAction(page, 'website-download'),
  ]);
  expect(download.suggestedFilename()).toBe('website.zip');
  await download.saveAs(test.info().outputPath('website.zip'));
  await page
    .getByRole('region', { name: 'Website content' })
    .getByRole('link', { name: 'Document', exact: true })
    .click();
  await page
    .locator('#document-editor')
    .fill('A private change after the release.');
  await page.getByRole('button', { name: 'More', exact: true }).click();
  await page.keyboard.press('Escape');
  // The edit has to reach the server before we navigate away from it. A goto
  // cancels whatever the page still had in flight, so an unflushed commit dies
  // with it, the website page then builds its draft from the document as it was,
  // and the preview shows the pre-edit text with nothing left to trigger a
  // rebuild. That is what the failing screenshot showed: a healthy page, the
  // preview rendering "This is the first published garden note.", and no
  // "Updating preview…" toolbar. The sibling spec does the same fill, More and
  // Escape and then waits here too.
  await waitForSynced(page);
  await page.goto(websiteURL);
  await page.getByRole('button', { name: 'More', exact: true }).click();
  await expect(prepare).toBeEnabled({ timeout: 30000 });
  await expect(
    preview.getByText('A private change after the release.'),
  ).toBeVisible();
  await websiteAction(page, 'website-show-release');
  await expect(
    preview.getByText('This is the first published garden note.'),
  ).toBeVisible();
  await expect(
    preview.getByText('A private change after the release.'),
  ).toHaveCount(0);
  await page.reload();
  await page.getByRole('button', { name: 'More', exact: true }).click();
  await expect(prepare).toBeEnabled({ timeout: 30000 });
  await expect(
    preview.getByText('A private change after the release.'),
  ).toBeVisible();
  await page.screenshot({
    path: test.info().outputPath('website-workspace.png'),
    fullPage: true,
  });
  const versionURL = await page.evaluate(async () => {
    const { hostingRequest } = window.atomicE2E.hostingClient;
    const subject = new URL(location.href).searchParams.get('subject')!;
    const status = await hostingRequest(window.store, subject);

    return `/app/show?subject=${encodeURIComponent(subject)}&view=website-version:${status.state!.deployments.at(-1)}`;
  });
  await page.goto(`${new URL(websiteURL).origin}${versionURL}`);
  await expect(
    page.getByRole('link', { name: 'Back to website', exact: true }),
  ).toBeVisible();
  await expect(
    preview.getByText('This is the first published garden note.'),
  ).toBeVisible();
  await expect(
    preview.getByText('A private change after the release.'),
  ).toHaveCount(0);
  await expect(page.locator('iframe[title="Website preview"]')).toHaveAttribute(
    'sandbox',
    'allow-same-origin',
  );
  await expect(
    page.getByRole('button', { name: 'Update site', exact: true }),
  ).toHaveCount(0);
  await page.screenshot({
    path: test.info().outputPath('website-export-preview.png'),
    fullPage: true,
  });
  await page.reload();
  await expect(
    preview.getByText('This is the first published garden note.'),
  ).toBeVisible();
});

// The model is scripted, but these are the real Assistant tools and Atomic writes.
test('Assistant creates and redesigns a website using existing table content', async ({
  page,
}) => {
  test.slow();
  let tableSubject = '';
  let rowSubject = '';
  let otherSubject = '';
  let documentSubject = '';
  const config = () => ({
    version: 1,
    title: 'Field notes',
    description: 'Ideas for small gardens',
    language: 'en',
    accent: '#315c49',
    background: '#f5f3eb',
    font: 'serif',
    css: 'header{padding:1.5rem 0}.intro{position:sticky;top:2rem}main{padding-top:3rem}h1{font-family:Georgia,serif;font-weight:400}.garden-notes{border-top:4px solid var(--accent);padding-top:1rem}.card{box-shadow:0 6px 24px #20302008}body{background:radial-gradient(ellipse at top left,#e4ebd7,transparent 55%),var(--paper)}',
    pages: [
      {
        path: '/',
        title: 'Home',
        sections: [
          { kind: 'intro', index: 0, span: 'half', className: 'garden-intro' },
          { kind: 'table', index: 0, span: 'half', className: 'garden-notes' },
        ],
        documents: [],
        tables: [
          {
            table: tableSubject,
            title: 'Growing notes',
            layout: 'grid',
            search: true,
            rows: [rowSubject, otherSubject],
            columns: [
              {
                property: 'https://atomicdata.dev/properties/name',
                label: 'Note',
              },
            ],
          },
        ],
      },
      {
        path: '/about/',
        title: 'About the garden',
        documents: [documentSubject],
        tables: [],
        sections: [
          { kind: 'intro', index: 0, span: 'half', className: 'about-garden' },
          {
            kind: 'document',
            index: 0,
            span: 'half',
            className: 'garden-story',
          },
        ],
      },
    ],
  });

  const websiteFrom = (results: string[]) => {
    for (const result of results) {
      const match = /"website"\s*:\s*"([^"]+)"/.exec(result);
      if (match) return match[1];
    }

    throw new Error('Assistant did not return a website.');
  };

  const state = await setupScriptedToolCallMocks(
    page,
    [
      { tool: 'create_website', args: () => ({ config: config() }) },
      {
        tool: 'describe_website',
        args: results => ({ website: websiteFrom(results) }),
      },
      {
        tool: 'update_website',
        args: results => ({
          website: websiteFrom(results),
          config: {
            ...config(),
            title: 'The garden notebook',
            accent: '#a64427',
            font: 'sans',
          },
        }),
      },
    ],
    'The website design is ready to preview.',
  );
  await enableAIForTesting(page);
  await before({ page });
  await page
    .getByRole('button', { name: 'New Document', exact: true })
    .first()
    .click();
  await page
    .locator('#document-editor')
    .fill(
      'A small garden can change the rhythm of a day. We collect practical growing notes for balconies, windowsills and city plots. Start with one plant, watch what changes, and keep a notebook. These notes are edited in Atomic; each website release preserves the version we chose to share.',
    );
  documentSubject = new URL(page.url()).searchParams.get('subject')!;
  expect(documentSubject).toBeTruthy();
  const fixture = await page.evaluate(async () => {
    const store = window.store;
    const name = 'https://atomicdata.dev/properties/name';
    const table = await store.newResource({
      parent: store.getDrive(),
      isA: ['https://atomicdata.dev/classes/Table'],
      propVals: {
        [name]: 'Garden notes',
        'https://atomicdata.dev/properties/classtype':
          'https://atomicdata.dev/classes/Resource',
      },
    });
    await table.save();
    const row = await store.newResource({
      parent: table.subject,
      propVals: {
        [name]: 'Sow spinach in September',
        'https://atomicdata.dev/properties/description':
          'PRIVATE FIELD MUST NOT EXPORT',
      },
    });
    await row.save();
    const unrelated = await store.newResource({
      parent: table.subject,
      propVals: { [name]: 'PRIVATE ROW MUST NOT EXPORT' },
    });
    await unrelated.save();
    const other = await store.newResource({
      parent: table.subject,
      propVals: { [name]: 'Grow rosemary on a sunny balcony' },
    });
    await other.save();

    return { table: table.subject, row: row.subject, other: other.subject };
  });
  tableSubject = fixture.table;
  rowSubject = fixture.row;
  otherSubject = fixture.other;
  // The right panel is transient state and is never restored from storage
  // (#1475), so the panel has to be opened before the chat input exists.
  // `sendChatMessage` does that, and waits out vector indexing and toasts.
  await sendChatMessage(
    page,
    'Make a website from my garden notes and refine the design.',
  );
  await expect(
    page.getByText('The website design is ready to preview.'),
  ).toBeVisible({ timeout: 60000 });
  expect(state.toolResults.join('\n')).toContain('checkedPages');
  expect(state.toolResults.join('\n')).toContain('updated');
  const subject = await page.evaluate(() => {
    let found = '';
    window.store.resources.forEach(resource => {
      if (
        resource.get('https://atomicdata.dev/properties/name') ===
        'The garden notebook'
      )
        found = resource.subject;
    });

    return found;
  });
  expect(subject).toBeTruthy();
  await page.goto(
    `${new URL(page.url()).origin}/app/show?subject=${encodeURIComponent(subject)}`,
  );
  // A full navigation can already close the transient panel. Close it only
  // when present: toggling AI would reopen it and steal focus from the menu.
  const closeAI = page.getByRole('button', {
    name: 'Close AI Sidebar',
    exact: true,
  });
  if (await closeAI.isVisible()) await closeAI.click();
  await expect(closeAI).toHaveCount(0);
  await expect(
    page.getByRole('button', { name: 'Publish site', exact: true }),
  ).toBeEnabled({ timeout: 30000 });
  await page.getByRole('button', { name: 'More', exact: true }).click();
  await expect(page.getByTestId('menu-item-website-prepare')).toBeEnabled({
    timeout: 30000,
  });
  await page.getByRole('button', { name: 'More', exact: true }).click();
  const preview = page.frameLocator('iframe[title="Website preview"]');
  await expect(
    preview.getByRole('heading', { name: 'The garden notebook', exact: true }),
  ).toBeVisible();
  await expect(
    preview
      .frameLocator('iframe[title="Search Growing notes"]')
      .getByText('Sow spinach in September'),
  ).toBeVisible();
  await expect(preview.getByText('PRIVATE FIELD MUST NOT EXPORT')).toHaveCount(
    0,
  );
  await expect(preview.getByText('PRIVATE ROW MUST NOT EXPORT')).toHaveCount(0);
  const search = preview.frameLocator('iframe[title="Search Growing notes"]');
  await expect(search.getByText('2 results', { exact: true })).toBeVisible();
  await expect(search.getByText('PRIVATE FIELD MUST NOT EXPORT')).toHaveCount(
    0,
  );
  await expect(search.getByText('PRIVATE ROW MUST NOT EXPORT')).toHaveCount(0);
  await search.getByRole('searchbox').fill('rosemary');
  await expect(search.getByText('1 results', { exact: true })).toBeVisible();
  await expect(search.getByText('Sow spinach in September')).toHaveCount(0);
  await search.getByRole('searchbox').fill('no such plant');
  await expect(search.getByText('No matching results')).toBeVisible();
  await search.getByRole('searchbox').fill('');
  await preview
    .getByRole('link', { name: 'About the garden', exact: true })
    .click();
  await expect(
    preview.getByRole('heading', { name: 'About the garden', exact: true }),
  ).toBeVisible();
  await preview.getByRole('link', { name: 'Home', exact: true }).click();
  await expect(search.getByRole('searchbox')).toBeVisible();
  await page.getByRole('button', { name: 'More', exact: true }).click();
  await page.getByTestId('menu-item-website-prepare').click();
  await page
    .getByRole('button', { name: 'Create release', exact: true })
    .click();
  const [siteDownload] = await Promise.all([
    page.waitForEvent('download'),
    websiteAction(page, 'website-download'),
  ]);
  await siteDownload.saveAs(test.info().outputPath('garden-site.zip'));
  await websiteAction(page, 'website-show-release');
  await page.getByRole('button', { name: 'Page edit', exact: true }).click();
  await expect(preview.locator('[contenteditable="true"]')).toHaveCount(2);
  const field = preview.locator('[contenteditable="true"]').first();
  // The three waits below guard the SAME thing: one inline-edit save, which is
  // `commitWebsiteField` re-reading the site config, checking the row still
  // belongs to the selected table, then `resource.save()`. Until it settles the
  // status line reads "Saving content…", so each of these was guarding a commit
  // round-trip with the 10 s `expect.timeout` default. `test.slow()` raises the
  // WALL, never the per-assertion budget, so it never covered them.
  //
  // Measured on this spec, store wiped, five rounds (three alone and two with
  // the other three website specs at four workers): the first of these saves
  // costs 1433, 1925, 3981, 4069 and 4150 ms, so 42% of the default at worst on
  // a quiet box. A CI shard runs ~71 tests against one server, and store growth
  // alone has been measured to more than double a step of this shape
  // (4533 ms to 10814 ms on `installation-recovery:96`), on top of three other
  // shards, clippy and the vitest suites. That is how develop run 4665 failed
  // all three attempts here with the page still reading "Saving content…".
  //
  // 30 s is ~7x the worst local sample and 3x the budget CI overran. The
  // neighbouring assistant wait at the top of this test already carries 60 s.
  // If this ever fails ON 30 s, that is not a budget any more: it means the
  // save really does not settle, and the place to look is the save counters
  // `waitForSynced` reads, not this number.
  const SAVE_TIMEOUT = 30_000;

  await field.fill('Plant winter lettuce in October');
  await page.getByText('Click an outlined field', { exact: false }).click();
  await expect(
    page.getByText('Content saved. The existing release is unchanged.'),
  ).toBeVisible({ timeout: SAVE_TIMEOUT });
  // Clearing a text field is an explicit write, not a silently ignored blur.
  await field.fill('');
  await page.getByText('Click an outlined field', { exact: false }).click();
  await expect
    .poll(
      async () =>
        page.evaluate(
          async row =>
            (await window.store.getResource(row)).get(
              'https://atomicdata.dev/properties/name',
            ),
          rowSubject,
        ),
      { timeout: SAVE_TIMEOUT },
    )
    .toBe('');
  await field.fill('Plant winter lettuce in October');
  await page.getByText('Click an outlined field', { exact: false }).click();
  await expect(
    page.getByText('Content saved. The existing release is unchanged.'),
  ).toBeVisible({ timeout: SAVE_TIMEOUT });
  const stored = await page.evaluate(
    async row =>
      (await window.store.getResource(row)).get(
        'https://atomicdata.dev/properties/name',
      ),
    rowSubject,
  );
  expect(stored).toBe('Plant winter lettuce in October');
  await page.getByRole('button', { name: 'Done editing', exact: true }).click();
  await expect(
    search.getByText('Plant winter lettuce in October'),
  ).toBeVisible();
  await websiteAction(page, 'website-show-release');
  await expect(preview.getByText('Sow spinach in September')).toBeVisible();
  await expect(preview.locator('[contenteditable]')).toHaveCount(0);
  await page.reload();
  await page.getByRole('button', { name: 'More', exact: true }).click();
  await expect(search.getByText('Plant winter lettuce in October')).toBeVisible(
    { timeout: 30000 },
  );
  await page.screenshot({
    path: test.info().outputPath('assistant-website.png'),
    fullPage: true,
  });
});

async function websiteAction(
  page: import('@playwright/test').Page,
  id: string,
) {
  const item = page.getByTestId('menu-item-' + id);
  if (!(await item.isVisible()))
    await page.getByRole('button', { name: 'More', exact: true }).click();
  await item.click();
}
