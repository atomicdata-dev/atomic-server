import { test, expect, type Page } from './fixtures';
import {
  before,
  editTitle,
  setTitle,
  contextMenuClick,
  timestamp,
  newResource,
  typeInSearch,
  searchAndOpen,
  getCurrentSubject,
  openSubject,
  waitForSearchIndex,
  smoke,
} from './test-utils';

const SEARCH_RESULTS = 'https://atomicdata.dev/properties/search/results';
const TAGS = 'https://atomicdata.dev/properties/tags';

async function waitForServerSearch(
  page: Page,
  query: string,
  parents: string,
  expectedSubjects: string[],
) {
  await page.waitForFunction(
    async args => {
      const store = (
        window as {
          store?: {
            getServerUrl(): string;
            fetchResourceFromServer(
              subject: string,
              opts: { noWebSocket: boolean },
            ): Promise<{ get(property: string): unknown }>;
          };
        }
      ).store;

      if (!store) return false;

      const url = new URL('/search', store.getServerUrl());
      url.searchParams.set('q', args.query);
      url.searchParams.set('parents', args.parents);
      url.searchParams.set('include', 'true');
      url.searchParams.set('limit', '10');

      try {
        const resource = await store.fetchResourceFromServer(url.toString(), {
          noWebSocket: true,
        });
        const results = resource.get(args.resultsProperty);

        return (
          Array.isArray(results) &&
          args.expectedSubjects.every(subject => results.includes(subject))
        );
      } catch {
        return false;
      }
    },
    {
      query,
      parents,
      expectedSubjects,
      resultsProperty: SEARCH_RESULTS,
    },
    { timeout: 30000, polling: 1000 },
  );
}

async function waitForFilteredServerSearch(
  page: Page,
  parents: string,
  tagSubjects: string[],
  expectedSubject: string,
) {
  for (const tagSubject of tagSubjects) {
    await expect
      .poll(
        () =>
          page.evaluate(
            async args =>
              window.store.search('', {
                parents: args.parents,
                filters: { [args.tagsProperty]: [args.tagSubject] },
                include: true,
                limit: 10,
              }),
            { parents, tagsProperty: TAGS, tagSubject },
          ),
        { timeout: 30000, intervals: [1000] },
      )
      .toContain(expectedSubject);
  }
}

// Tests rewritten for the modal search overlay. Old behavior (inline address
// bar auto-navigating to /app/search?query=...) no longer exists. New flow:
// open overlay (cmd+K or the Search button), type a query, pick a result.
test.describe('search', async () => {
  test.beforeEach(before);

  test('text search', smoke, async ({ page }) => {
    // Seed content: dev-drive starts empty, so we create the thing we intend
    // to find. Previously the test relied on onboarding content ("Welcome to
    // your drive…") that no longer ships with dev-drive. Avoid colons in the
    // name (the overlay parses `tag:...` specially).
    const driveSubject = await getCurrentSubject(page);
    const unique = Date.now().toString(36);
    const targetName = `Searchable-Folder-${unique}`;
    await newResource('folder', page);
    await setTitle(page, targetName);
    const folderSubject = await getCurrentSubject(page);

    // Don't rely on a fixed 6.5s sleep — under parallel load the index can
    // lag noticeably longer. Poll the real search endpoint until the new
    // folder appears. Probe the server resource directly so local KV hits
    // don't make this readiness check pass before Tantivy is committed.
    await waitForServerSearch(page, unique, driveSubject, [folderSubject]);

    // Go somewhere else so navigation via search is observable.
    await openSubject(page, driveSubject);

    await searchAndOpen(page, unique, targetName);
    await expect(page.getByRole('heading', { name: targetName })).toBeVisible();
  });

  test('scoped search', async ({ page }) => {
    const driveSubject = await getCurrentSubject(page);

    // Create folder called 'Salad folder'
    await newResource('folder', page);
    await setTitle(page, 'Salad folder');

    // Create document called 'Avocado Salad'
    await page
      .getByRole('main')
      .getByRole('button', { name: 'New Document' })
      .click();
    await editTitle('Avocado Salad', page);
    const avocadoSaladSubject = await getCurrentSubject(page);

    // Create folder called 'Cake folder' at root
    await openSubject(page, driveSubject);
    await newResource('folder', page);
    await setTitle(page, 'Cake Folder');
    await expect(
      page.getByRole('heading', { name: 'Cake Folder' }),
    ).toBeVisible();
    const cakeFolderSubject = await getCurrentSubject(page);

    // Create document called 'Avocado Cake'
    await page
      .getByRole('main')
      .getByRole('button', { name: 'New Document' })
      .click();
    await editTitle('Avocado Cake', page);
    const avocadoCakeSubject = await getCurrentSubject(page);

    await openSubject(page, cakeFolderSubject);

    // Wait until the server's scoped search index actually contains the
    // doc. A fixed sleep races the ~5s index-commit throttle; poll the
    // real scoped query (`parents` forces the server path) instead.
    await waitForServerSearch(page, 'Avocado', cakeFolderSubject, [
      avocadoCakeSubject,
    ]);

    // Set search scope to 'Cake folder'
    await page.reload();
    // Wait for the navbar's resource to actually be Cake Folder before
    // opening the context menu. The menu's `subject` prop comes from the
    // navbar resource, which falls back to the drive while the real one
    // is still loading — clicking `scope` then sets the scope to the drive
    // instead of Cake Folder and the assertion sees the wrong result set.
    await expect(
      page.locator(`main[about="${cakeFolderSubject}"]`).first(),
    ).toBeVisible({ timeout: 20000 });
    await contextMenuClick('scope', page);

    // Scoped-only results: Avocado Cake is under Cake folder; Avocado Salad is not.
    await typeInSearch(page, 'Avocado');
    const searchResults = page.locator('[data-index]');
    await expect(
      searchResults.filter({ hasText: 'Avocado Cake' }).first(),
    ).toBeVisible();
    await expect(
      searchResults.filter({ hasText: 'Avocado Salad' }),
    ).toHaveCount(0);

    // Remove scope — the modal overlay does not render the old searchbar's
    // clear-scope chip, so reopen the current subject without `queryscope`.
    await page.keyboard.press('Escape');
    await openSubject(page, cakeFolderSubject);

    // Salad doc was indexed for an earlier scoped query (different `parents`)
    // so the un-scoped server index doesn't necessarily contain it yet.
    // Poll the drive-scoped search (matching the overlay's `parents: drive`
    // default) until both docs are returned — without this, a slow indexer
    // under parallel load races the assertion.
    await waitForServerSearch(page, 'Avocado', driveSubject, [
      avocadoCakeSubject,
      avocadoSaladSubject,
    ]);
    // The server having both docs is not the signal this assertion needs: the
    // overlay renders what `store.search` returns, which answers from the
    // CLIENT index. Poll that same call until both are in it — otherwise the
    // un-scoped assertion races a local index the reload above had to rebuild.
    await waitForSearchIndex(page, 'Avocado', 2);

    await typeInSearch(page, 'Avocado');
    await expect(
      searchResults.filter({ hasText: 'Avocado Cake' }).first(),
    ).toBeVisible();
    await expect(
      searchResults.filter({ hasText: 'Avocado Salad' }).first(),
    ).toBeVisible();
  });

  test('add tags and search for them', async ({ page }) => {
    const folderName = `TagTestFolder-${timestamp()}`;
    await newResource('folder', page);
    await setTitle(page, folderName);
    const driveSubject = await page.evaluate(() => window.store.getDrive());
    const folderSubject = await getCurrentSubject(page);

    // Add tags via the TagBar
    const firstTagName = `first-tag`;
    await page
      .locator('[aria-label="navigation"] button')
      .filter({ hasText: 'Tags' })
      .click();
    await page.getByPlaceholder('New tag').fill(firstTagName);
    await page.getByTitle('Add tag').click();
    await expect(
      page.locator('[aria-label="navigation"]').getByText(firstTagName),
    ).toBeVisible();

    const secondTagName = `second-tag`;
    await expect(page.getByPlaceholder('New tag')).toHaveValue('');
    await page.getByPlaceholder('New tag').fill(secondTagName);
    await page.getByTitle('Add tag').click();
    await expect(
      page.locator('[aria-label="navigation"]').getByText(secondTagName),
    ).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(
      page.getByTestId('sidebar').getByRole('button', { name: firstTagName }),
    ).toBeVisible();
    await expect(
      page.getByTestId('sidebar').getByRole('button', { name: secondTagName }),
    ).toBeVisible();

    const tagSubjects = await page.evaluate(
      async ({ subject, tagsProperty }) => {
        const folder = await window.store.getResource(subject);

        return folder.get(tagsProperty) as string[];
      },
      { subject: folderSubject, tagsProperty: TAGS },
    );
    expect(tagSubjects).toHaveLength(2);

    // Tag filters go through PropValSub; wait for the exact filtered
    // query instead of sleeping for an assumed index interval.
    await waitForFilteredServerSearch(
      page,
      driveSubject ?? '',
      tagSubjects,
      folderSubject,
    );

    // Search by first tag — result should include our folder.
    await searchAndOpen(page, `tag:${firstTagName}`, folderName);
    await expect(page.getByRole('heading', { name: folderName })).toBeVisible();

    // Search by second tag
    await searchAndOpen(page, `tag:${secondTagName}`, folderName);
    await expect(page.getByRole('heading', { name: folderName })).toBeVisible();

    // Non-existent tag — overlay shows no match, close with Escape.
    await typeInSearch(page, `tag:nonexistent-tag`);
    await expect(
      page.locator('[data-index]').filter({ hasText: folderName }),
    ).toHaveCount(0);
    await page.keyboard.press('Escape');
  });

  // Offline search must resolve from the ClientDb KV index — no server
  // round-trip. A regression here makes search silently return nothing
  // while disconnected.
  test('search works offline against the local index', async ({
    page,
    context,
  }) => {
    test.slow();

    // Create a folder with a distinctive name while online.
    const unique = `OfflineFindable-${timestamp()}`;
    await newResource('folder', page);
    await setTitle(page, unique);

    // It must be in the store (and therefore the local search index) before
    // we cut the connection.
    await expect(page.getByTestId('sidebar').getByText(unique)).toBeVisible({
      timeout: 10000,
    });

    // The folder is created (commit 1) and named via `setTitle` (commit 2);
    // the KV index only picks up the *name* once that rename commit
    // applies. The sidebar shows the name optimistically well before.
    // Wait for ClientDb.search — `store.search()` online merges `/search`
    // and would mask a local-index miss.
    await expect
      .poll(
        async () =>
          page.evaluate(async q => {
            const store = window.store as unknown as {
              getDrive(): string | undefined;
              getClientDb():
                | {
                    isReady: boolean;
                    search(
                      query: string,
                      opts?: { parents?: string },
                    ): Promise<string[]>;
                  }
                | undefined;
            };

            try {
              const db = store.getClientDb();
              const drive = store.getDrive();

              if (!db?.isReady || !drive) return 0;

              return (await db.search(q, { parents: drive })).length;
            } catch {
              return 0;
            }
          }, unique),
        { timeout: 15000 },
      )
      .toBeGreaterThan(0);

    // Finish loading the fonts already used by the page before cutting the
    // network; an in-flight font download is unrelated to offline indexing.
    await page.evaluate(async () => {
      const downloads: Promise<FontFace>[] = [];
      document.fonts.forEach(face => downloads.push(face.load()));
      await Promise.all(downloads);
      await document.fonts.ready;
    });
    // Go offline: block the network and close the WebSocket.
    await context.setOffline(true);
    await page.evaluate(() => {
      (
        window as unknown as {
          store?: { getDefaultWebSocket(): { close(): void } | undefined };
        }
      ).store
        ?.getDefaultWebSocket()
        ?.close();
    });
    await page.waitForFunction(
      () => window.store?.getSyncStatus().serverConnected === false,
      undefined,
      { timeout: 15000 },
    );

    // Search while offline — must surface the folder from the local index.
    // Exclude the "Start AI Chat with …" fallback row: it echoes the query
    // text, so a plain `hasText` match would pass even with zero real
    // results.
    await typeInSearch(page, unique);
    await expect(
      page
        .locator('[data-index]')
        .filter({ hasText: unique })
        .filter({ hasNotText: 'Start AI Chat' })
        .first(),
    ).toBeVisible({ timeout: 10000 });
  });
});
