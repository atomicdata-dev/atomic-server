import { test, expect } from './fixtures';
import { before } from './test-utils';

/**
 * Regressions for the two ways a locally-cached drive has been lost across an
 * offline reload:
 *
 * 1. Durability. ClientDb's per-write redb commits use `Durability::None`;
 *    only a later `flush()` (Immediate commit) persists them. The browser
 *    worker used to never flush, so every local write rolled back on reload —
 *    invisible online (the server re-caches), fatal offline. The worker now
 *    flushes on a 1s tick, and this test asks for the flush explicitly.
 *
 * 2. Boot ordering. The app attaches its ClientDb a few hundred ms into boot
 *    (`initClientDb` derives the agent's database name and unwraps its key
 *    first) — AFTER React's first render on a production bundle. A fetch
 *    mounting in that window found no database, read the silence as a miss,
 *    and offline failed the drive with "Offline: resource not available
 *    locally" — permanently, with the data sitting in OPFS. The store now
 *    distinguishes "no database to ask" from "asked, not there" and waits out
 *    the announced attach before failing (`Store.expectClientDb`).
 */
test('cached drive survives reload while offline', async ({ page }) => {
  await before({ page }); // devDrive — creates + visits a drive online

  // Wait for ClientDb + the drive's OPFS write — a bare timeout races
  // WASM init under dagger (clientdb.init alone can exceed 2s). Mirror
  // `offline-reload.spec.ts`.
  // `window.store` is assigned during boot, so this has to tolerate it being
  // absent rather than throw: under a slow boot the unguarded form fails with
  // "Cannot read properties of undefined", which reports a TypeError instead
  // of whatever actually went wrong. Reproduced locally at
  // ATOMIC_TEST_CPU_THROTTLE=8.
  await page.waitForFunction(
    () => window.store?.getClientDb()?.isReady === true,
    undefined,
    { timeout: 30000 },
  );
  await page.waitForFunction(
    async () => {
      const drive = window.store?.getDrive();
      if (!drive) return false;
      const jsonAd = await window.store?.getClientDb()?.getResource?.(drive);

      return !!jsonAd;
    },
    undefined,
    { timeout: 15000 },
  );

  // The write landing is not the same as the write being durable: per-write
  // commits use `Durability::None` and are only persisted by a later Immediate
  // commit, which the worker otherwise schedules on a 1s tick. A reload before
  // that tick rolls the write back — which is the exact bug under test, so ask
  // for the flush and wait for it rather than racing the timer.
  await page.evaluate(async () => {
    const db = window.store.getClientDb();

    // Not optional-chained: `?.flush()` on an absent ClientDb is a silent
    // no-op, and the test would go on to reload and fail with the same
    // props=0 it was written to catch — blaming durability for a database
    // that was never there.
    if (!db) throw new Error('ClientDb missing when asking for a flush');

    await db.flush();
  });

  const drive = await page.evaluate(() => window.store.getDrive());

  // Go offline (what the Sync-page "disconnect" does) and reload.
  await page.evaluate(() => localStorage.setItem('ws-disconnected', '1'));
  await page.reload();

  await page.waitForFunction(
    () => window.store?.getClientDb()?.isReady === true,
    undefined,
    { timeout: 30000 },
  );

  const r = await page.evaluate(async d => {
    const s = window.store;
    let viaGet = -1; // -1 ⇒ the read threw (e.g. the offline-unavailable error)

    try {
      const g = await s.getResource(d);
      viaGet = g?.getEntries ? g.getEntries().length : 0;
    } catch {
      viaGet = -1;
    }

    // Read-only diagnostics, gathered BEFORE anything mutates the store: an
    // earlier version of this test deleted the cached resource to probe a
    // retry, which replaced the failed entry — so the report's `error` field
    // described the fresh copy and hid the actual failure for days. These
    // three tell the failure modes apart without touching anything:
    // whether the drive was persisted to OPFS at all, whether what's stored
    // would pass the store's "renderable" guard, and what state the store's
    // cached entry is in.
    let inClientDb = false;
    let storedProps = -1;
    let storedHasClass = false;

    try {
      const jsonAd = await s.getClientDb()?.getResource?.(d);
      inClientDb = !!jsonAd;

      if (jsonAd) {
        const parsed = JSON.parse(jsonAd) as Record<string, unknown>;
        storedProps = Object.keys(parsed).length;
        storedHasClass = 'https://atomicdata.dev/properties/isA' in parsed;
      }
    } catch {
      inClientDb = false;
    }

    const cached = s.resources.get(d);

    return {
      viaGetProps: viaGet,
      serverConnected: s.getSyncStatus?.()?.serverConnected,
      inClientDb,
      storedProps,
      storedHasClass,
      cachedState: cached
        ? `loading=${cached.loading} error=${cached.error?.message ?? 'none'} n=${
            cached.getEntries?.().length
          }`
        : 'ABSENT',
    };
  }, drive ?? '');

  // We must actually be offline (proves we're testing the local cache, not a
  // server re-fetch), and the drive must still resolve from the ClientDb.
  expect(r.serverConnected).toBe(false);
  expect(
    r.viaGetProps,
    `drive should load from OPFS offline; got props=${r.viaGetProps} ` +
      `inClientDb=${r.inClientDb} storedProps=${r.storedProps} ` +
      `storedHasClass=${r.storedHasClass} cached=${r.cachedState}. ` +
      (r.inClientDb
        ? 'The drive IS in OPFS, so the store failed to read it back offline.'
        : 'The drive is NOT in OPFS, so the write did not survive the reload.'),
  ).toBeGreaterThan(0);
});
