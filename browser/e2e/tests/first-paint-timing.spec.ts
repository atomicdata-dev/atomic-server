import { test } from './fixtures';
import {
  SERVER_URL,
  FRONTEND_URL,
  devDrive,
  currentDriveTitle,
} from './test-utils';
import { applyCpuThrottle, envCpuThrottle } from './perf-attach';

/**
 * Measures the latency from `goto` to "the resource's title is visible".
 *
 * For the SSR meta-tag fast path to work, the test must hit atomic-server
 * directly (port 9883) — Vite's `index.html` (6747) doesn't carry the
 * `<meta property="json-ad-initial">` tag.
 *
 * Flow:
 *   1. `devDrive()` creates an agent + drive (writes secret to localStorage).
 *   2. Capture the drive subject URL from `window.location`.
 *   3. Reload that URL from atomic-server (so SSR emits the meta tag).
 *   4. Time until the drive title is in the DOM.
 *
 * The meta tag should flatten propvals into `_cache` synchronously during
 * `parseMetaTags()`, so the title appears WELL before Loro's WASM
 * download completes.
 */
// Perf-instrumentation test: cross-origin navigates from Vite (6747) to
// atomic-server (9883) to exercise the SSR meta-tag fast path.
// localStorage isn't shared between origins, so the SPA on 9883 starts
// agent-less and the drive title doesn't render. Run with
// `PROFILE_PERF=1` when measuring; skip otherwise.
test.skip(
  !process.env.PROFILE_PERF,
  'perf-instrumentation only; run with PROFILE_PERF=1',
);
test('first paint timing — meta-tag fast path', async ({ page }) => {
  // Generous overall budget — devDrive + cold cold-load + probes can
  // run >30s under 10x CPU throttle on contended runners.
  test.setTimeout(120_000);
  const throttle = envCpuThrottle();
  if (throttle) await applyCpuThrottle(page, throttle);

  // Setup: create dev drive (agent + drive in localStorage).
  await devDrive(page);

  // Now grab the drive URL — devDrive ends on the drive page.
  const driveUrlInFrontend = page.url();
  // Swap the vite dev host (FRONTEND_URL) for atomic-server (SERVER_URL) so the
  // SSR meta-tag is emitted.
  const driveUrl = driveUrlInFrontend.replace(FRONTEND_URL, SERVER_URL);

  // Cold-navigate to the drive directly on atomic-server.
  const t0 = Date.now();
  await page.goto(driveUrl);
  const gotoMs = Date.now() - t0;

  await currentDriveTitle(page).waitFor({ state: 'visible', timeout: 15000 });
  const titleVisibleMs = Date.now() - t0;

  // When does the first sidebar child link render? This is the real
  // "is the sidebar useful" moment — it gates on Collection.fetchPage,
  // which used to wait for OPFS seed. With the race-server-vs-OPFS fix,
  // it should land well before the WASM seed completes.
  let firstSidebarChildMs = -1;

  try {
    await page.waitForSelector('[data-test="resource-sidebar"]', {
      timeout: 2000,
    });
    firstSidebarChildMs = Date.now() - t0;
  } catch {
    // Drive may have no children — leave as -1.
  }

  const loroLoadedAt = await page.evaluate(async () => {
    const start = performance.now();

    while (performance.now() - start < 5000) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const loaded = (globalThis as any).LoroLoader?.isLoaded?.();
      if (loaded) return performance.now();
      await new Promise(r => setTimeout(r, 50));
    }

    return -1;
  });

  // eslint-disable-next-line no-console
  console.log(`[first-paint] throttle=${throttle ?? 1}x via ${driveUrl}`);
  // eslint-disable-next-line no-console
  console.log(`  goto returned:     ${gotoMs} ms`);
  // eslint-disable-next-line no-console
  console.log(`  title visible:     ${titleVisibleMs} ms`);
  // eslint-disable-next-line no-console
  console.log(
    `  1st sidebar child: ${firstSidebarChildMs < 0 ? 'n/a (no children)' : firstSidebarChildMs + ' ms'}`,
  );
  // eslint-disable-next-line no-console
  console.log(
    `  Loro ready @page:  ${loroLoadedAt < 0 ? 'never' : Math.round(loroLoadedAt) + ' ms'}`,
  );
});
