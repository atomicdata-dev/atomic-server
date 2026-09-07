/**
 * Perf-budget probe: captures a `__atomicPerf` snapshot for several
 * representative flows and writes them as test attachments. Use to
 * compare local-vs-CI timings (and to find a CPU throttle rate that
 * matches dagger).
 *
 * Run flavors:
 *   - vanilla local:               `pnpm test-e2e perf-budgets.spec.ts`
 *   - throttled to dagger speed:   `ATOMIC_TEST_CPU_THROTTLE=4 pnpm test-e2e perf-budgets.spec.ts`
 *
 * The attached `perf-trace` JSON has both the raw events (timestamps +
 * durations relative to test start) and a sorted rollup. Skim the
 * rollup for any single span hitting double-digit ms — those are the
 * paths that turn into 10s+ flakes when CI runs them on a slower box.
 *
 * Probes:
 *   - cold-load: first paint after dev-drive bootstrap.
 *   - reconnect: disconnect → reconnect → drive sync.
 *   - genesis-creates: rapid-fire create of N folders to time the
 *     `pushCommits` round-trip distribution.
 */

import { test, expect } from './fixtures';
import {
  before,
  newResource,
  waitForServerConnected,
  waitForSynced,
} from './test-utils';
import { attachPerfSnapshot, resetPerfTrace } from './perf-attach';

test.describe('perf budgets', () => {
  test.beforeEach(before);

  test('cold load: dev-drive bootstrap + first paint', async ({
    page,
  }, testInfo) => {
    // `before` already navigated us; capture what happened.
    await waitForServerConnected(page, 15_000);
    await attachPerfSnapshot(page, testInfo, 'perf-cold-load');
  });

  test('reconnect: close WS + drive sync', async ({ page }, testInfo) => {
    await waitForServerConnected(page, 15_000);

    // Reset so the snapshot only contains the disconnect→reconnect window.
    await resetPerfTrace(page);

    // Use the store's `reconnect()` API directly — calling `close()` on
    // the underlying WS hits the `_closed=true` branch and the auto-
    // retry loop never re-fires, so the test would just hang waiting
    // for `serverConnected===true`.
    const syncBefore = await page.evaluate(
      () => window.store.getSyncStatus().lastDriveSync?.timestamp ?? 0,
    );
    await page.evaluate(() => {
      window.store.reconnect();
    });
    await waitForServerConnected(page, 15_000);
    await page.waitForFunction(
      beforeTs =>
        (window.store?.getSyncStatus().lastDriveSync?.timestamp ?? 0) >
        beforeTs,
      syncBefore,
      { timeout: 15_000 },
    );

    await attachPerfSnapshot(page, testInfo, 'perf-reconnect');
  });

  test('genesis-creates: 5 sequential new folders', async ({
    page,
  }, testInfo) => {
    await waitForServerConnected(page, 15_000);
    await resetPerfTrace(page);

    // Create N folders in a row via the same sidebar flow other specs
    // use, then wait for each commit to be acked before the next create.
    // Rapid-fire creates exercise the `postCommit` round-trip — and
    // they're a very close mirror of the failure shape we see in CI's
    // chatroom / tables / table-refresh tests.
    const N = 5;

    for (let i = 0; i < N; i++) {
      await newResource('folder', page);
      await waitForSynced(page, 10_000);
    }

    // Reference `expect` to avoid an unused-import warning when this
    // probe is later trimmed; actual assertion is implicit (must not
    // throw within timeouts).
    expect(N).toBe(5);

    await attachPerfSnapshot(page, testInfo, 'perf-genesis-creates');
  });
});
