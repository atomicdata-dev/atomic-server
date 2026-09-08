import { test, expect } from './fixtures';
import { before } from './test-utils';

/**
 * Initialization performance probe — focuses on the WASM/OPFS ClientDb boot.
 *
 * Not a pass/fail budget gate: it drives the app through a cold boot (empty
 * OPFS → seed) and a warm reload (OPFS populated → rehydrate) and prints the
 * per-phase `__atomicPerf` breakdown that the new `clientdb.*` instrumentation
 * emits (incl. worker-side WASM-import / instantiate / OPFS-open timings folded
 * back across the worker boundary). Run with:
 *
 *   npx playwright test tests/opfs-init-perf.spec.ts --workers=1 --reporter=line
 *
 * and read the `[INIT-PERF]` lines.
 */

interface PerfRollupRow {
  name: string;
  count: number;
  totalMs: number;
  maxMs: number;
  avgMs: number;
}

const CLIENTDB_PREFIXES = ['clientdb.', 'ws.open', 'store.'];

async function captureInitPerf(page: import('@playwright/test').Page) {
  // Wait until the ClientDb reports ready, then snapshot the trace.
  await page.waitForFunction(
    () => window.store?.getClientDb?.()?.isReady === true,
    undefined,
    { timeout: 30000 },
  );

  return page.evaluate(prefixes => {
    const snap = (
      window as unknown as {
        __atomicPerf?: {
          snapshot(): {
            windowMs: number;
            rollup: PerfRollupRow[];
            events: Array<{ name: string; t: number; d?: number; p?: unknown }>;
          };
        };
      }
    ).__atomicPerf?.snapshot();

    if (!snap) return { error: 'no __atomicPerf' };

    const interesting = (n: string) => prefixes.some(p => n.startsWith(p));

    // Per-phase marks/spans relevant to init, in time order.
    const events = snap.events
      .filter(e => interesting(e.name) && !e.name.endsWith(':start'))
      .map(e => ({
        name: e.name,
        at: Math.round(e.t),
        dur: e.d !== undefined ? Math.round(e.d * 100) / 100 : undefined,
        p: e.p,
      }));

    // Navigation + WASM resource fetch (browser-native timing).
    const nav = performance.getEntriesByType(
      'navigation',
    )[0] as PerformanceNavigationTiming;
    const wasm = performance
      .getEntriesByType('resource')
      .filter(r => /wasm|client-db|atomic_wasm/i.test(r.name))
      .map(r => ({
        name: r.name.split('/').slice(-1)[0].split('?')[0],
        startMs: Math.round(r.startTime),
        durMs: Math.round(r.duration),
        size: (r as PerformanceResourceTiming).transferSize,
      }));

    return {
      windowMs: snap.windowMs,
      navigation: nav
        ? {
            responseEndMs: Math.round(nav.responseEnd),
            domContentLoadedMs: Math.round(nav.domContentLoadedEventEnd),
            loadEventMs: Math.round(nav.loadEventEnd),
          }
        : undefined,
      wasmFetch: wasm,
      events,
    };
  }, CLIENTDB_PREFIXES);
}

test.describe('init performance (OPFS / WASM ClientDb)', () => {
  test.beforeEach(before);
  test.slow();

  test('cold boot (empty OPFS → seed) and warm reload (OPFS → rehydrate)', async ({
    page,
  }) => {
    // `before` already ran devDrive, so OPFS is populated and the trace holds
    // this session's init. Snapshot it as the WARM(ish) baseline first.
    const warm1 = await captureInitPerf(page);
    // eslint-disable-next-line no-console
    console.log('[INIT-PERF] warm (post-devDrive):', JSON.stringify(warm1));

    // COLD boot: wipe OPFS + the bootstrap fingerprint, then reload. The
    // ClientDb re-inits against an empty OPFS, so the seed path runs.
    await page.evaluate(async () => {
      try {
        const root = await navigator.storage.getDirectory();

        for await (const [name] of root.entries()) {
          await root
            .removeEntry(name, { recursive: true })
            .catch(() => undefined);
        }
      } catch {
        // ignore
      }

      localStorage.removeItem('atomic.client-db.bootstrap-fingerprint');
    });
    await page.reload({ waitUntil: 'domcontentloaded' });
    const cold = await captureInitPerf(page);
    // eslint-disable-next-line no-console
    console.log('[INIT-PERF] COLD (empty OPFS → seed):', JSON.stringify(cold));

    // WARM reload: OPFS now populated from the cold boot; reload skips the seed
    // and goes through rehydrate.
    await page.reload({ waitUntil: 'domcontentloaded' });
    const warm2 = await captureInitPerf(page);
    // eslint-disable-next-line no-console
    console.log(
      '[INIT-PERF] WARM (OPFS populated → rehydrate):',
      JSON.stringify(warm2),
    );

    // VERSION CHANGE: a non-null but stale fingerprint must trigger a FULL
    // (unfiltered) reseed so changed default values overwrite — correctness
    // path, expected to be slower (one-time per version bump).
    await page.evaluate(() => {
      localStorage.setItem(
        'atomic.client-db.bootstrap-fingerprint',
        'STALE:deadbeef',
      );
    });
    await page.reload({ waitUntil: 'domcontentloaded' });
    const versionChange = await captureInitPerf(page);
    // eslint-disable-next-line no-console
    console.log(
      '[INIT-PERF] VERSION-CHANGE (stale fingerprint → full reseed):',
      JSON.stringify(versionChange),
    );

    // Sanity: the trace must actually contain the new clientdb marks.
    expect(
      (cold as { events?: unknown[] }).events?.length ?? 0,
    ).toBeGreaterThan(0);
  });
});
