import { test, expect } from './fixtures';
import { FRONTEND_URL, currentDriveTitle } from './test-utils';
import { applyCpuThrottle, envCpuThrottle } from './perf-attach';

/**
 * Granular timing for the devDrive bootstrap path that fails in CI.
 * Reports each phase so we can see WHICH phase eats the budget on a
 * slow runner.
 */

async function timeIt<T>(
  label: string,
  fn: () => Promise<T>,
): Promise<{ label: string; ms: number; result: T }> {
  const start = Date.now();
  const result = await fn();

  return { label, ms: Date.now() - start, result };
}

test.describe('dev-drive timing', () => {
  // Phase-timing measurement only; skip under regular CI runs.
  test.skip(
    !process.env.PROFILE_PERF,
    'perf-instrumentation only; run with PROFILE_PERF=1',
  );
  test('full devDrive() flow', async ({ page }) => {
    const throttle = envCpuThrottle();
    if (throttle) await applyCpuThrottle(page, throttle);

    const t0 = Date.now();

    const goto = await timeIt('goto /app/dev-drive', () =>
      page.goto(`${FRONTEND_URL}/app/dev-drive`),
    );

    const waitForURL = await timeIt('waitForURL did:ad:', () =>
      page.waitForURL(/did(?:%3A|:)ad(?:%3A|:)/, { timeout: 30000 }),
    );

    const waitForTitle = await timeIt('currentDriveTitle visible', () =>
      expect(currentDriveTitle(page)).toBeVisible({ timeout: 15000 }),
    );

    const total = Date.now() - t0;

    // eslint-disable-next-line no-console
    console.log(`[devDrive timing] throttle=${throttle ?? 1}x`);
    // eslint-disable-next-line no-console
    console.log(`  goto:           ${goto.ms} ms`);
    // eslint-disable-next-line no-console
    console.log(`  waitForURL:     ${waitForURL.ms} ms`);
    // eslint-disable-next-line no-console
    console.log(`  waitForTitle:   ${waitForTitle.ms} ms`);
    // eslint-disable-next-line no-console
    console.log(`  TOTAL:          ${total} ms`);

    // Also pull the store's perfTrace snapshot for the per-span breakdown.
    const perf = await page.evaluate(() => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return (window as any).__atomicPerf?.snapshot?.() ?? null;
    });

    if (perf?.rollup) {
      // eslint-disable-next-line no-console
      console.log(`[perf rollup] ${perf.count} events in ${perf.windowMs}ms`);

      for (const r of perf.rollup.slice(0, 10)) {
        // eslint-disable-next-line no-console
        console.log(
          `  ${r.name.padEnd(35)} n=${String(r.count).padStart(3)}  total=${String(r.totalMs).padStart(7)}ms  max=${String(r.maxMs).padStart(7)}ms`,
        );
      }
    }
  });
});
