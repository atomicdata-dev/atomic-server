import { test, expect } from './fixtures';
import {
  before,
  getDevDriveSecret,
  FRONTEND_URL,
  smoke,
  expectPkarrLookupMiss,
} from './test-utils';

/**
 * A second device (or a fresh/cleared OPFS) must load an existing drive's
 * contents from the server. Device 1 creates a folder; device 2 — a brand-new
 * browser context with an empty local DB, same agent — opens the drive and
 * must see the folder (drive sync populates the local index / server `/query`
 * fallback). Guards the cold-load path that the OPFS durability fix and the
 * collection server-fallback depend on.
 */
test(
  'a fresh-OPFS second device loads an existing drive’s contents',
  smoke,
  async ({ browser, browserDiagnostics }) => {
    expectPkarrLookupMiss(browserDiagnostics);
    const ctx1 = await browser.newContext();
    const p1 = await ctx1.newPage();
    await before({ page: p1 });
    const drive = await p1.evaluate(async () => {
      const s = window.store;
      const d = s.getDrive();

      if (!d) throw new Error('no drive');

      const f = await s.newResource({
        deferGenesis: true,
        parent: d,
        isA: 'https://atomicdata.dev/classes/Folder',
      });
      await f.set(
        'https://atomicdata.dev/properties/name',
        'SecondDeviceChild',
        false,
      );
      await f.save();

      return d;
    });
    const secret = await getDevDriveSecret(p1);

    // Device 1 is about to be closed, so the folder has to have reached the
    // server before that — device 2 has an empty OPFS and can only load it from
    // there. This was a flat 2s sleep, which is a guess at how long a commit
    // takes and was simply wrong on a loaded CI runner: the context closed with
    // the commit still queued, and the failure landed on device 2 as "the drive
    // is missing its contents", pointing at the cold-load path this test exists
    // to check rather than at the setup that never completed.
    await p1.waitForFunction(
      () => window.store?.getSyncStatus().pendingDirtyCount === 0,
      undefined,
      { timeout: 30_000 },
    );
    await ctx1.close();

    const ctx2 = await browser.newContext(); // brand-new context ⇒ empty OPFS
    const p2 = await ctx2.newPage();
    await p2.goto(
      `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(drive)}`,
    );

    // Open the private drive as a returning device actually would. The
    // generic root-page helper can mistake a public sidebar for a signed-in
    // session and return without ever entering the secret.
    await expect(
      p2.getByRole('heading', { name: 'Unlock this drive' }),
    ).toBeVisible({ timeout: 20_000 });
    await p2.getByLabel('Agent secret').fill(secret);

    // 12000 was not enough, and the way it failed matters: "element(s) not
    // found" is the same sentence this test produced when the child genuinely
    // never arrived, which was a product bug (c95dd96). It is not that any
    // more. Six four-worker rounds with this assertion opened up to 60s all
    // passed, the child landing at 10851, 11166, 11798, 12743, 13099 and
    // 13307ms, while the same mix failed 2 of 4 at 12000. The child arrives;
    // the assertion was giving up first.
    //
    // So this waits for a cold boot plus a whole drive sync, and 30s is a bit
    // over twice the slowest arrival seen rather than a round number.
    await expect(p2.getByText('SecondDeviceChild').first()).toBeVisible({
      timeout: 30_000,
    });
    await ctx2.close();
  },
);
