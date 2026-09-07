/**
 * ClientDb Web Locks leadership — the basics.
 *
 * The ClientDb (WASM, single-writer) uses `navigator.locks` to elect ONE leader
 * tab per origin; other tabs are followers that proxy DB calls to the leader
 * over a BroadcastChannel. This verifies the election works and that a second
 * tab coexists without hard-failing — including on Firefox, which lacks the
 * Chromium-only lock-steal recovery path (see `lib/src/client-db.ts`). Runs in
 * both chromium and firefox (see the `firefox` project in playwright.config.ts).
 */
import { test, expect, type Page } from './fixtures';
import { before, FRONTEND_URL } from './test-utils';

/** Poll until the tab's ClientDb is ready and reported no init error. */
async function expectClientDbReady(page: Page): Promise<void> {
  await expect
    .poll(
      () =>
        page.evaluate(() => {
          const s = window.store?.getSyncStatus();

          return {
            ready: s?.clientDbReady ?? false,
            error: s?.clientDbError ?? null,
          };
        }),
      { timeout: 15000 },
    )
    .toEqual({ ready: true, error: null });
}

test.describe('ClientDb Web Locks leadership', () => {
  test.beforeEach(before);

  test('a second tab coexists under the shared origin lock', async ({
    page,
    context,
  }) => {
    // `before()` left `page` as the elected leader for this origin.
    await expectClientDbReady(page);

    // A second tab shares the origin's Web Locks namespace. It must become a
    // follower (not hard-fail election) and stay usable — on Firefox too.
    const page2 = await context.newPage();
    await page2.goto(FRONTEND_URL);
    await expectClientDbReady(page2);
  });
});
