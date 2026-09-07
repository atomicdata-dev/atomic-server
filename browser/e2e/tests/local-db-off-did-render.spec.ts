import { test, expect } from './fixtures';
import {
  currentDriveTitle,
  FRONTEND_URL,
  waitForServerConnected,
} from './test-utils';
import { applyCpuThrottle } from './perf-attach';

/**
 * Repro for the user's exact sequence: Local DB OFF *from the start* (so OPFS
 * is never used), then create a dev-drive, then refresh. The drive is a DID
 * resource fetched purely from the server. The bug: after refresh it renders
 * "deeply broken" — raw subject as the H1, no class view — and (server-only)
 * stays that way.
 *
 * Local DB off means `initClientDb` never runs, so this is NOT the OPFS
 * cold-load path; the resource comes only from `fetchResourceFromServer`.
 */
test('a DID drive renders (not bare subject) with Local DB off, server-only', async ({
  page,
}) => {
  // Disable Local DB before ANY app script runs, on every navigation — mirrors
  // the Sync-page toggle persisting across reloads.
  await page.addInitScript(() => {
    localStorage.setItem('atomic-disable-client-db', '1');
  });

  await page.goto(`${FRONTEND_URL}/app/dev-drive`);
  await page.waitForURL(/did(?:%3A|:)ad(?:%3A|:)/, { timeout: 30000 });
  await expect(currentDriveTitle(page)).toBeVisible({ timeout: 15000 });

  const drive = await page.evaluate(() => window.store.getDrive());

  // Sanity: Local DB really is off (server-only path under test).
  expect(await page.evaluate(() => !window.store.getClientDb())).toBe(true);

  // The user's trigger: refresh while viewing the DID drive.
  await page.goto(
    `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(drive ?? '')}`,
  );

  // Diagnostics: wait until the store holds the drive's class, then snap.
  await waitForServerConnected(page);
  await page.waitForFunction(
    d => {
      const s = window.store;
      s?.getResource(d).catch(() => undefined);
      const r = s?.resources.get(d);

      return !!r?.get?.('https://atomicdata.dev/properties/isA');
    },
    drive ?? '',
    { timeout: 15_000 },
  );
  const diag = await page.evaluate(d => {
    const s = window.store;
    const r = s.resources.get(d);

    return {
      present: !!r,
      loading: r?.loading ?? null,
      error: r?.error?.message ?? null,
      isA: (r?.get?.('https://atomicdata.dev/properties/isA') ??
        null) as unknown,
      entries: r?.getEntries ? r.getEntries().length : -1,
      serverConnected: s.getSyncStatus?.()?.serverConnected ?? null,
    };
  }, drive ?? '');
  console.log('[did-render] post-refresh drive state:', JSON.stringify(diag));

  // The drive must render its real view (title), NOT the bare DID subject.
  await expect(currentDriveTitle(page)).toBeVisible({ timeout: 15000 });
  const driveTitleText = await currentDriveTitle(page).innerText();
  expect(driveTitleText).not.toContain('did:ad:');

  // --- Now the folder case (what the user actually views) ---
  // Create a Folder server-only (Local DB still off), then refresh on it and
  // sample tightly for a window where it is loading=false with no class and no
  // error — the "deeply broken" flash. With Local DB off there's no cache to
  // paper over it.
  const folder = await page.evaluate(async d => {
    const s = window.store;
    const tmp = await s.createSubject('ld');
    const f = await s.newResource({
      subject: tmp,
      parent: d,
      isA: 'https://atomicdata.dev/classes/Folder',
    });
    await f.set(
      'https://atomicdata.dev/properties/name',
      'OffStartFolder',
      false,
    );
    await f.save();

    return f.subject;
  }, drive ?? '');

  await page.goto(
    `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(folder)}`,
  );

  // Slow the CPU to widen any cold-load race (the user's real machine loses to
  // it), then hard-reload on the folder — the user's "refresh" gesture.
  await applyCpuThrottle(page, 8);
  await page.reload();

  // Under CPU throttling, page.reload() can resolve before App.tsx exposes the
  // store. Start sampling as soon as the store exists, not before bootstrapping.
  await page.waitForFunction(() => !!window.store, undefined, {
    timeout: 15000,
  });

  // Sample as fast as possible after the navigation for the broken window.
  const samples = await page.evaluate(async f => {
    const s = window.store;
    const out: Array<{
      t: number;
      loading: boolean | null;
      error: string | null;
      isA: boolean;
    }> = [];
    const start = performance.now();

    s.getResource(f).catch(() => undefined);

    // Sampling a race window, not waiting for readiness: we need ~2s of
    // snapshots to catch a settled-but-contentless flash. 25ms is the
    // sample interval, not a "hope it landed" sleep.
    for (let i = 0; i < 80; i++) {
      const r = s.resources.get(f);
      out.push({
        t: Math.round(performance.now() - start),
        loading: r?.loading ?? null,
        error: r?.error?.message ? 'err' : null,
        isA: !!r?.get?.('https://atomicdata.dev/properties/isA'),
      });
      await new Promise(res => setTimeout(res, 25));
    }

    return out;
  }, folder);

  // A "broken" sample = settled (not loading), no error, but no class to render.
  const brokenSamples = samples.filter(
    s => s.loading === false && !s.error && !s.isA,
  );
  console.log(
    '[did-render] folder broken-window samples:',
    brokenSamples.length,
    'of',
    samples.length,
    'first few:',
    JSON.stringify(samples.slice(0, 8)),
  );

  // The folder must end up rendered as a folder.
  await expect(
    page.getByRole('heading', { name: 'OffStartFolder' }),
  ).toBeVisible({ timeout: 15000 });

  // And it must NEVER have been shown as a settled-but-contentless resource.
  expect(brokenSamples.length).toBe(0);
});
