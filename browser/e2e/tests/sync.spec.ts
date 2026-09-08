import { test, expect } from './fixtures';
import {
  before,
  editableTitle,
  currentDriveTitle,
  FRONTEND_URL,
  getDevDriveSecret,
  waitForClientDbFlush,
  waitForClientDbReady,
  waitForSearchIndex,
  waitForServerConnected,
  waitForSynced,
  smoke,
} from './test-utils';

test.describe('sync', () => {
  test.beforeEach(before);

  test(
    'create resource online, edit title, verify it persists across reload',
    smoke,
    async ({ page }) => {
      // 1. Create a document in the drive (online)
      await page
        .getByTestId('sidebar')
        .getByRole('button', { name: 'New Document' })
        .click();

      await expect(editableTitle(page)).toBeVisible({ timeout: 10000 });

      // Set title
      await editableTitle(page).click();
      await expect(editableTitle(page)).toHaveRole('textbox');
      await editableTitle(page).fill('Sync Test Doc');
      await page.keyboard.press('Escape');

      // Wait for the title to be committed to the server
      await expect(
        page.getByTestId('sidebar').getByText('Sync Test Doc'),
      ).toBeVisible({ timeout: 10000 });

      // Wait for server to process the commit and rebuild index
      await page.waitForFunction(
        () => window.store?.getSyncStatus().pendingDirtyCount === 0,
        undefined,
        { timeout: 10000 },
      );

      // 2. Reload and verify persistence
      await page.reload({ waitUntil: 'domcontentloaded' });
      await expect(currentDriveTitle(page)).toBeVisible({ timeout: 15000 });

      // The document should be accessible (not unauthorized)
      await expect(
        page.getByTestId('sidebar').locator('a').first(),
      ).toBeVisible({
        timeout: 15000,
      });
    },
  );

  test('edits made offline persist across reload', async ({ page }) => {
    test.slow();

    // 1. Create a document while online.
    //
    // CRITICAL: wait for the URL to flip off the drive page before
    // touching `editableTitle`. The drive page ALSO has an editable
    // title; if we proceed before the click→navigate window closes,
    // we end up renaming the DRIVE and the rest of the test
    // (offline edit, reload, expect) operates on a different
    // resource than intended. Confirmed via debug logging:
    // `main[about] === store.getDrive()` immediately after the
    // click, so `editableTitle` resolved to the drive's input.
    const driveUrl = page.url();
    await page
      .getByTestId('sidebar')
      .getByRole('button', { name: 'New Document' })
      .click();
    await page.waitForURL(url => url.toString() !== driveUrl, {
      timeout: 10000,
    });

    await expect(editableTitle(page)).toBeVisible({ timeout: 10000 });
    await editableTitle(page).click();
    await expect(editableTitle(page)).toHaveRole('textbox');
    await editableTitle(page).fill('Before Offline');
    await page.keyboard.press('Escape');

    // Wait for the title to be committed
    await expect(
      page.getByTestId('sidebar').getByText('Before Offline'),
    ).toBeVisible({ timeout: 10000 });

    // Get the resource subject for the post-reload poll below.
    const resourceSubject = await page.evaluate(() => {
      const main = document.querySelector('main[about]');

      return main?.getAttribute('about');
    });
    expect(resourceSubject).toBeTruthy();

    // 2. Go offline
    await page.evaluate(() => {
      window.store.getDefaultWebSocket()?.close();
    });

    // Wait until the store notices the disconnect
    await page.waitForFunction(
      () => window.store?.getSyncStatus().serverConnected === false,
      undefined,
      { timeout: 10000 },
    );

    // 3. Edit the title while offline
    await editableTitle(page).click();
    await expect(editableTitle(page)).toHaveRole('textbox');
    await editableTitle(page).fill('Edited Offline');
    await page.keyboard.press('Escape');

    // Wait for the edit to be saved locally — and for OPFS to actually
    // hold the new title. `pendingDirtyCount > 0` alone is not enough
    // under dagger load: ClientDb init + the durable flush can lag the
    // dirty bit, and a reload before the snapshot lands lets a server
    // GET of "Before Offline" win the race.
    await page.waitForFunction(
      () => window.store?.getSyncStatus().pendingDirtyCount > 0,
      undefined,
      { timeout: 10000 },
    );
    await page.waitForFunction(
      async ({ subject }) => {
        const clientDb = window.store.getClientDb();
        if (!clientDb?.isReady) return false;
        const jsonAd = await clientDb.getResource?.(subject);
        if (!jsonAd) return false;

        try {
          const parsed = JSON.parse(jsonAd) as Record<string, unknown>;
          const name = parsed['https://atomicdata.dev/properties/name'];

          return name === 'Edited Offline';
        } catch {
          return false;
        }
      },
      { subject: resourceSubject! },
      { timeout: 15000 },
    );

    // Stay offline across the reload so this test asserts OPFS durability
    // rather than racing a reconnect GET of the pre-offline server title.
    await page.evaluate(() => localStorage.setItem('ws-disconnected', '1'));

    // 4. Reload the page
    await page.reload({ waitUntil: 'domcontentloaded' });
    await waitForClientDbReady(page);

    // Wait for the resource itself to report the offline edit before
    // asserting on the DOM. `waitForClientDbReady` only confirms the worker/
    // OPFS bootstrap finished, not that THIS resource's local-first fetch
    // has resolved — under a contended runner that can outlast a bare
    // `toBeVisible` poll.
    await page.waitForFunction(
      ({ subject }) =>
        window.store.getResourceLoading(subject).title === 'Edited Offline',
      { subject: resourceSubject! },
      { timeout: 30000 },
    );

    // 5. Verify the offline edit survived the reload (the title appears in
    // the breadcrumb, sidebar tree, and main editable title — match the
    // main one to avoid strict-mode multi-match).
    await expect(
      page.getByTestId('editable-title').getByText('Edited Offline'),
    ).toBeVisible({ timeout: 15000 });
  });

  // FLAKY, two independent known causes:
  //
  // 1. (dagger CI + remote CI) on the second-context (page2) view of
  //    the document, the `Synced From Offline` H1 doesn't render within
  //    30 s. Path is page1 edits offline → reconnect → page1
  //    `waitForSearchable` → page2 navigates to the resource subject.
  //    Already does a `waitForFunction` against `store.resources.get(...)`,
  //    but under dagger CPU contention the Loro WASM init + WS
  //    authenticate + GET round-trip exceeds the budget. Investigate:
  //    pre-warm Loro on page2 before navigation, or split the deadline so
  //    the WS GET budget is independent of the H1 render budget.
  //
  // 2. (local, 2026-07-02) the EARLIER `serverConnected === false` wait
  //    (below, step 2) also times out intermittently — NOT a CI/dagger
  //    thing, reproduces locally with no other processes competing for
  //    CPU. Root-caused, not just relabeled "environmental": see the
  //    comment at that `waitForFunction` call for the actual race. Fixed
  //    2026-08-25: `WsClient.close()` now flips `serverConnected` and fails
  //    pending requests synchronously (see websockets.ts).
  test('offline edits sync to server when connection is restored', async ({
    page,
    context,
    browser,
  }) => {
    test.slow();

    // 1. Create a document while online.
    //
    // CRITICAL: wait for the URL to flip to the new doc's subject before
    // touching `editableTitle`. The drive page also has an editable
    // title; if the click→navigate window is wide enough (server under
    // load) we'd be targeting the drive's title input and end up
    // renaming the DRIVE to "Will Edit Offline" instead of the doc.
    // Later assertions (`sidebar.getByText('Will Edit Offline')`) would
    // still pass because the drive's title also shows in the sidebar,
    // masking the bug until the second context fails to find the doc.
    const driveUrl = page.url();
    await page
      .getByTestId('sidebar')
      .getByRole('button', { name: 'New Document' })
      .click();
    await page.waitForURL(url => url.toString() !== driveUrl, {
      timeout: 10000,
    });

    await expect(editableTitle(page)).toBeVisible({ timeout: 10000 });
    await editableTitle(page).click();
    await expect(editableTitle(page)).toHaveRole('textbox');
    await editableTitle(page).fill('Will Edit Offline');
    await page.keyboard.press('Escape');

    // Wait for the title to be committed
    await expect(
      page.getByTestId('sidebar').getByText('Will Edit Offline'),
    ).toBeVisible({ timeout: 10000 });

    // Get the resource subject for later verification
    const resourceSubject = await page.evaluate(() => {
      const main = document.querySelector('main[about]');

      return main?.getAttribute('about');
    });

    expect(resourceSubject).toBeTruthy();

    // Get the secret so we can sign in from another context
    const secret = await getDevDriveSecret(page);

    // Make sure the lazy `CollaborativeEditor` chunk is loaded BEFORE going
    // offline, otherwise the document body falls into an ErrorBoundary and
    // the editable title disappears. Vite serves these chunks dynamically;
    // setOffline(true) blocks the fetch.
    await expect(page.getByLabel('Rich Text Editor')).toBeVisible({
      timeout: 15000,
    });

    // 2. Go offline using Playwright's network control + close the WS
    // directly. `setOffline(true)` blocks new connections but doesn't tear
    // down the open one, so the store's `serverConnected` flag won't flip
    // until something forces a close. Closing here also halts auto-retry
    // (close() sets `_closed=true`) so the backoff doesn't pile up.
    await context.setOffline(true);
    await page.evaluate(() => {
      window.store.getDefaultWebSocket()?.close();
    });

    // Wait for the store to detect the disconnect.
    //
    // FLAKY (2026-07-02, root-caused): this times out intermittently even
    // with zero other processes competing for CPU (ruled out: leftover
    // dev-server processes, parallel-worker contention — both were tried
    // and disproven; earlier attribution to "environmental" flakiness was
    // wrong). Trace evidence: on a failing run, a commit still in flight
    // from step 1 hits its own 10s internal timeout ("COMMIT timed out
    // after 10000ms... using HTTP") only AFTER `setOffline(true)` + the
    // manual `close()` above have already run — meaning the WS `close`
    // event (the only thing that calls `setServerConnected(false)`, see
    // `websockets.ts`) didn't fire promptly. Suspected cause: a race
    // between Playwright's CDP-level `setOffline(true)` network block and
    // the manual `ws.close()` call — Chromium may suppress or delay the
    // `close` event once the transport is already CDP-blocked. Not fixed
    // here — tracked in planning/sync.md's Test coverage gaps. Likely fix: don't rely
    // on the `close` event for local closes; have `WsClient.close()` call
    // `setServerConnected(false)` (and `rejectAllPending`) synchronously
    // itself, since the caller already knows it initiated the close.
    await page.waitForFunction(
      () => window.store?.getSyncStatus().serverConnected === false,
      undefined,
      { timeout: 15000 },
    );

    // 3. Edit title offline
    await editableTitle(page).click();
    await expect(editableTitle(page)).toHaveRole('textbox');
    await editableTitle(page).fill('Synced From Offline');
    await page.keyboard.press('Escape');

    // Wait for dirty count to increase AND for OPFS to hold the offline
    // title — otherwise a reload-before-flush races the reconnect drain
    // into an empty export that used to clear the dirty bit (see
    // `drainOutboxSubject` offline baseVersion recovery).
    await page.waitForFunction(
      () => window.store?.getSyncStatus().pendingDirtyCount > 0,
      undefined,
      { timeout: 10000 },
    );
    await page.waitForFunction(
      async ({ subject }) => {
        const clientDb = window.store.getClientDb();
        if (!clientDb?.isReady) return false;
        const jsonAd = await clientDb.getResource?.(subject);
        if (!jsonAd) return false;

        try {
          const parsed = JSON.parse(jsonAd) as Record<string, unknown>;

          return (
            parsed['https://atomicdata.dev/properties/name'] ===
            'Synced From Offline'
          );
        } catch {
          return false;
        }
      },
      { subject: resourceSubject! },
      { timeout: 15000 },
    );

    // The offline edit is in the ClientDb, but "written" is not "durable":
    // per-write commits use `Durability::None` and only survive a reload once
    // an Immediate commit lands, which the worker otherwise schedules on a 1s
    // tick. The reload below would roll the edit back, and the server would
    // never hear about it — which is exactly this test's failure mode, right
    // down to the fresh context reading the pre-offline title.
    await waitForClientDbFlush(page, { required: true });

    // 4. Go back online — navigate to force fresh WS connection
    await context.setOffline(false);
    // Reload establishes a fresh store + WS
    await page.reload({ waitUntil: 'domcontentloaded' });
    await waitForServerConnected(page);

    // The dirty sync should push the offline edit to the server.
    // Wait for all pending resources to sync.
    await waitForSynced(page);

    // Wait for the search index to pick up the change
    await waitForSearchIndex(page, 'Synced From Offline');

    // Ask the server for its own copy over HTTP, bypassing every local cache.
    // The two waits above both have blind spots — `waitForSynced` proves the
    // dirty bit cleared (which a poisoned drain can do without delivering
    // anything: it once exported the offline delta from a server-hydrated doc
    // and the ack cleared dirty), and `waitForSearchable` merges page1's own
    // LOCAL index. This is the assertion that the edit actually left this
    // machine; the second context below then proves a fresh device sees it.
    // Poll: drains can still be running when the waits release.
    await expect
      .poll(
        () =>
          page.evaluate(
            async ({ subject }) => {
              const fresh = await window.store.fetchResourceFromServer(
                subject,
                { setLoading: true, noWebSocket: true },
              );

              return fresh?.title;
            },
            { subject: resourceSubject! },
          ),
        { timeout: 30000, intervals: [1000] },
      )
      .toBe('Synced From Offline');

    // 5. Open a fresh browser context (simulates another device)
    const context2 = await browser.newContext();
    const page2 = await context2.newPage();
    await page2.goto(`${FRONTEND_URL}/app/agent`);

    // Sign in with the same agent
    await page2.getByRole('button', { name: 'Sign in', exact: true }).click();
    // No confirm button: the flow signs in as soon as the secret parses.
    const secretField = page2.getByLabel('Agent secret');
    await secretField.fill(secret);
    // No blur: the field disables itself the moment the secret parses (it
    // shows "Signing in…"), and `blur()` on a disabled input waits for an
    // actionability that never comes. `waitForConnected` below is the real
    // signal that the sign-in took, so wait for that instead.

    // Wait for the second page to connect
    await waitForServerConnected(page2);

    // Navigate to the resource — the legacy `adress-bar` input is gone;
    // route directly via the SPA's /app/show entry.
    await page2.goto(
      `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(resourceSubject!)}`,
    );

    // Fresh context (no local cache) — title must come from the server,
    // proving the reconnect drain actually POSTed the offline delta.
    // (Previously an empty-export path cleared the outbox dirty bit
    // without POSTing; `waitForSearchable` hid that via the local index.)
    await expect
      .poll(async () => page2.title(), { timeout: 60000, intervals: [500] })
      .toBe('Synced From Offline');

    await context2.close();
  });

  test('sync page shows correct status', async ({ page }) => {
    await page.goto(`${FRONTEND_URL}/app/sync`);

    await expect(page.getByText('This device', { exact: true })).toBeVisible({
      timeout: 10000,
    });
    await expect(
      page.getByRole('heading', { name: 'Sync', exact: true }),
    ).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('Developer', { exact: true })).toBeVisible({
      timeout: 10000,
    });
  });
});
