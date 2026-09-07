import { test } from './fixtures';
import { FRONTEND_URL, currentDriveTitle } from './test-utils';
import { applyCpuThrottle, envCpuThrottle } from './perf-attach';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Records a Chrome DevTools `Performance` trace (Tracing.start/stop) for
 * the dev-drive bootstrap, saves it as a `.json` artifact that can be
 * loaded into `chrome://tracing` or speedscope.app to see WHERE the
 * 4-30s budget is going.
 *
 * Run with:
 *   ATOMIC_TEST_CPU_THROTTLE=10 pnpm exec playwright test dev-drive-profile.spec.ts --headed
 * (headed mode is required for Tracing.start over CDP)
 *
 * The trace lands in `e2e/dev-drive-trace.json`. Open with:
 *   - chrome://tracing → Load
 *   - or https://www.speedscope.app
 */

// CDP-tracing profiler; requires `--headed` and is not part of CI runs.
test.skip(
  !process.env.PROFILE_PERF,
  'perf-instrumentation only; run with PROFILE_PERF=1 and --headed',
);
test('dev-drive CDP trace', async ({ page }) => {
  const throttle = envCpuThrottle();
  if (throttle) await applyCpuThrottle(page, throttle);

  const client = await page.context().newCDPSession(page);

  await client.send('Tracing.start', {
    categories:
      'devtools.timeline,disabled-by-default-devtools.timeline,disabled-by-default-devtools.timeline.frame,toplevel,blink.console,blink.user_timing,latencyInfo,disabled-by-default-v8.cpu_profiler,disabled-by-default-devtools.timeline.stack',
    options: 'sampling-frequency=10000',
    transferMode: 'ReturnAsStream',
  });

  const t0 = Date.now();
  await page.goto(`${FRONTEND_URL}/app/dev-drive`);
  await page.waitForURL(/did(?:%3A|:)ad(?:%3A|:)/, { timeout: 30000 });
  await currentDriveTitle(page).waitFor({ state: 'visible', timeout: 30000 });
  const total = Date.now() - t0;

  // eslint-disable-next-line no-console
  console.log(
    `[trace] devDrive full flow: ${total} ms (throttle ${throttle ?? 1}x)`,
  );

  // Stop tracing and stream the result to disk.
  const traceCompleted = new Promise<string>((resolve, reject) => {
    client.on('Tracing.tracingComplete', async (event: { stream?: string }) => {
      if (!event.stream) return reject(new Error('No trace stream returned'));
      const chunks: string[] = [];

      while (true) {
        const { data, eof } = await client.send('IO.read', {
          handle: event.stream,
        });
        chunks.push(data);
        if (eof) break;
      }

      await client.send('IO.close', { handle: event.stream });
      resolve(chunks.join(''));
    });
  });

  await client.send('Tracing.end');
  const trace = await traceCompleted;

  const outPath = path.join(
    process.cwd(),
    `dev-drive-trace-throttle-${throttle ?? 1}x.json`,
  );
  fs.writeFileSync(outPath, trace);
  // eslint-disable-next-line no-console
  console.log(
    `[trace] saved to ${outPath} (${(trace.length / 1024).toFixed(0)} KB)`,
  );
});
