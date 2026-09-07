import { test, expect } from './fixtures';
import {
  before,
  getDevDriveSecret,
  signIn,
  FRONTEND_URL,
  smoke,
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
  async ({ browser }) => {
    const ctx1 = await browser.newContext();
    const p1 = await ctx1.newPage();
    await before({ page: p1 });
    const drive = await p1.evaluate(async () => {
      const s = window.store;
      const d = s.getDrive();

      if (!d) throw new Error('no drive');

      const tmp = await s.createSubject('sd');
      const f = await s.newResource({
        subject: tmp,
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
    await p2.goto(FRONTEND_URL);
    await signIn(p2, secret);
    await p2.goto(
      `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(drive)}`,
    );

    await expect(p2.getByText('SecondDeviceChild').first()).toBeVisible({
      timeout: 12000,
    });
    await ctx2.close();
  },
);
