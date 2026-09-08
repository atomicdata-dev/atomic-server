import { test } from './fixtures';
import {
  SERVER_URL,
  FRONTEND_URL,
  devDrive,
  currentDriveTitle,
} from './test-utils';

/**
 * Detailed first-paint breakdown — where does the 800ms post-goto window go?
 *
 * Captures Navigation Timing, top resource loads by transfer + duration,
 * Long Tasks, paint timings, and (if instrumented) user marks from the app.
 */
// Perf-instrumentation test: cross-origin navigates from Vite (6747) to
// atomic-server (9883). localStorage isn't shared between origins, so
// the SPA on 9883 starts agent-less and can't render the drive title.
// Run explicitly with `PROFILE_PERF=1` when measuring; skip otherwise.
test.skip(
  !process.env.PROFILE_PERF,
  'perf-instrumentation only; run with PROFILE_PERF=1',
);
test('first paint — phase breakdown', async ({ page }) => {
  await devDrive(page);
  const driveUrl = page.url().replace(FRONTEND_URL, SERVER_URL);

  // Start collecting Long Tasks BEFORE navigation.
  await page.addInitScript(() => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const longTasks: any[] = [];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (globalThis as any).__longTasks = longTasks;

    try {
      const obs = new PerformanceObserver(list => {
        for (const e of list.getEntries()) {
          longTasks.push({
            name: e.name,
            startTime: Math.round(e.startTime),
            duration: Math.round(e.duration),
          });
        }
      });
      obs.observe({ type: 'longtask', buffered: true });
    } catch {
      // older browsers
    }
  });

  await page.goto(driveUrl);
  await currentDriveTitle(page).waitFor({ state: 'visible', timeout: 15000 });

  const report = await page.evaluate(() => {
    const nav = performance.getEntriesByType(
      'navigation',
    )[0] as PerformanceNavigationTiming;
    const paints = performance.getEntriesByType('paint');
    const resources = performance.getEntriesByType(
      'resource',
    ) as PerformanceResourceTiming[];

    // Top 10 resources by responseEnd - startTime
    const byDuration = resources
      .map(r => ({
        name: r.name.split('/').slice(-2).join('/'),
        duration: Math.round(r.responseEnd - r.startTime),
        size: Math.round((r.transferSize || r.encodedBodySize || 0) / 1024),
        kind: r.initiatorType,
      }))
      .sort((a, b) => b.duration - a.duration)
      .slice(0, 10);

    return {
      nav: {
        ttfb: Math.round(nav.responseStart - nav.requestStart),
        responseEnd: Math.round(nav.responseEnd - nav.fetchStart),
        domInteractive: Math.round(nav.domInteractive - nav.fetchStart),
        domContentLoaded: Math.round(
          nav.domContentLoadedEventEnd - nav.fetchStart,
        ),
        loadEvent: Math.round(nav.loadEventEnd - nav.fetchStart),
        transfer: Math.round((nav.transferSize || 0) / 1024),
      },
      paints: paints.map(p => ({
        name: p.name,
        time: Math.round(p.startTime),
      })),
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      longTasks: (globalThis as any).__longTasks?.slice(0, 15) ?? [],
      topResources: byDuration,
    };
  });

  // eslint-disable-next-line no-console
  console.log('\n=== Navigation Timing ===');
  // eslint-disable-next-line no-console
  console.log(JSON.stringify(report.nav, null, 2));
  // eslint-disable-next-line no-console
  console.log('\n=== Paints ===');
  // eslint-disable-next-line no-console
  console.log(JSON.stringify(report.paints, null, 2));
  // eslint-disable-next-line no-console
  console.log('\n=== Top 10 resources by duration ===');
  // eslint-disable-next-line no-console
  console.table(report.topResources);
  // eslint-disable-next-line no-console
  console.log('\n=== Long Tasks (top 15) ===');
  // eslint-disable-next-line no-console
  console.table(report.longTasks);
});
