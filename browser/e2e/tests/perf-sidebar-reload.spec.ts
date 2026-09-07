// oxlint-disable no-await-in-loop
/**
 * Probe for the dagger flake pattern "sidebar text/link not visible
 * within 15s after reload".
 *
 * Repro shape (matches `sync.spec.ts:64` and `e2e.spec.ts:441`):
 *   1. Create a resource online (gets a server-acked commit + OPFS persist).
 *   2. Reload the page.
 *   3. Assert the sidebar shows the new resource within 15s.
 *
 * Instead of just asserting, this spec dumps the perf trace so we can
 * see what `@tomic/lib` did between reload and the sidebar query: how
 * long auth took, how long VV-sync took, whether dirty resources
 * dragged the timeline. Run with:
 *   ATOMIC_TEST_CPU_THROTTLE=8 pnpm test-e2e perf-sidebar-reload.spec.ts
 *
 * The captured snapshot lands in the test's `outputDir` as
 * `perf-sidebar-after-reload.json` and a compact rollup is printed to
 * stdout for skimming.
 */

import { test, expect } from './fixtures';
import { before, editableTitle, setTitle } from './test-utils';
import { attachPerfSnapshot, resetPerfTrace } from './perf-attach';
import { CollectionBuilder } from '@tomic/lib';

test.describe('perf: sidebar after reload', () => {
  test.beforeEach(before);

  test('create + reload: sidebar item visibility timing', async ({
    page,
  }, testInfo) => {
    // Phase A: click "New Document" → editable title appears on the
    // NEW document's page. The previous version only waited for an
    // `editableTitle` to be visible — but the drive page also has
    // one, and under load the click→navigate gap was long enough
    // that `setTitle` (Phase B) ran against the drive's title input
    // before the navigate landed. That renamed the drive instead of
    // the doc and the polling waitForFunction never saw
    // `name === 'Perf Probe Doc'` on the doc subject.
    //
    // Wait for the URL to flip to the new document's subject before
    // touching the title.
    const driveUrl = page.url();
    const phaseA_start = Date.now();
    await page
      .getByTestId('sidebar')
      .getByRole('button', { name: 'New Document' })
      .click();
    await page.waitForURL(url => url.toString() !== driveUrl, {
      timeout: 10000,
    });
    await expect(editableTitle(page)).toBeVisible({ timeout: 10000 });
    const phaseA_ms = Date.now() - phaseA_start;

    // Phase B: enter title + Escape → commit fires. Use the `setTitle`
    // helper rather than a raw `.fill()` + Escape so we get the
    // built-in `waitForCommitOnCurrentResource` waiter — `.fill()`
    // alone leaves the title save racing the input unmount, and we
    // saw the commit POST silently skipped on local re-runs.
    const phaseB_start = Date.now();
    await setTitle(page, 'Perf Probe Doc');

    // Phase C: sidebar shows the doc title (this is the assertion that
    // flakes in dagger). Poll the DOM directly so we can distinguish
    // "slow render" from "stuck pipeline" — the snapshot at the failure
    // point shows nothing, but if the text appears at e.g. t+12s after
    // a 10s assertion budget, that's just slowness, not deadlock.
    const phaseC_start = Date.now();

    const sidebarText = await page.evaluate(async () => {
      const target = 'Perf Probe Doc';
      const sidebar = document.querySelector('[data-testid="sidebar"]');
      const start = performance.now();
      const samples: { ms: number; hasText: boolean }[] = [];

      while (performance.now() - start < 16000) {
        const has = !!sidebar?.textContent?.includes(target);
        samples.push({
          ms: Math.round(performance.now() - start),
          hasText: has,
        });

        if (has) break;

        await new Promise(r => setTimeout(r, 200));
      }

      return samples;
    });
    const phaseC_ms = Date.now() - phaseC_start;
    const phaseB_ms = phaseC_start - phaseB_start;
    const firstHit = sidebarText.find(s => s.hasText);
    // eslint-disable-next-line no-console
    console.log(
      `[perf] sidebar polling: first hit at ${firstHit ? firstHit.ms + 'ms' : 'NEVER'}` +
        ` (samples: ${sidebarText.length}, last sample at ${sidebarText[sidebarText.length - 1]?.ms}ms)`,
    );

    if (!firstHit) {
      // Always attach the perf snapshot first — without this, the throw
      // below skips it and we lose the diagnostic data we came for.
      await attachPerfSnapshot(page, testInfo, 'perf-sidebar-stuck');

      const dump = await page.evaluate(async () => {
        const drive = window.store.getDrive();
        // The drive's children query — same params as `useChildren(drive)`.
        const childrenInStore: string[] = [];
        const resources = window.store.resources;

        if (resources && drive) {
          for (const [subject, r] of resources) {
            if (
              r?.get?.('https://atomicdata.dev/properties/parent') === drive
            ) {
              childrenInStore.push(subject);
            }
          }
        }

        // Also do a fresh collection query — same params useChildren
        // uses — to see if the collection layer reports the doc.
        let freshCollectionMembers: string[] | string = 'no-collection-builder';

        try {
          if (CollectionBuilder && drive) {
            const c = new CollectionBuilder(window.store, drive)
              .setProperty('https://atomicdata.dev/properties/parent')
              .setValue(drive)
              .build();
            await c.waitForReady();
            const total = c.totalMembers;
            const members: string[] = [];

            for (let i = 0; i < total; i++) {
              const m = await c.getMemberWithIndex(i);

              if (m) members.push(m);
            }

            freshCollectionMembers = members;
          }
        } catch (e) {
          freshCollectionMembers = 'err: ' + (e as Error).message;
        }

        const sidebar = document.querySelector('[data-testid="sidebar"]');

        return {
          drive,
          inMemoryChildren: childrenInStore,
          freshCollectionMembers,
          sidebarText: sidebar?.textContent?.slice(0, 600),
          syncStatus: window.store.getSyncStatus(),
        };
      });
      // eslint-disable-next-line no-console
      console.log('[perf] failure state:', JSON.stringify(dump, null, 2));
    }

    expect(firstHit, 'sidebar text never appeared').toBeTruthy();

    // eslint-disable-next-line no-console
    console.log(
      `[perf] phases: A(click→editable)=${phaseA_ms}ms` +
        ` B(fill+escape)=${phaseB_ms}ms` +
        ` C(escape→sidebar-text)=${phaseC_ms}ms`,
    );

    // Wait for the commit to actually reach the server. Reloading
    // before this means the next session has nothing to sync.
    await page.waitForFunction(
      () => window.store?.getSyncStatus().pendingDirtyCount === 0,
      undefined,
      { timeout: 10000 },
    );

    // 2. Reset the perf trace right before reload — we only want the
    // reload→sidebar window in the snapshot.
    await resetPerfTrace(page);

    const reloadStart = Date.now();
    await page.reload({ waitUntil: 'domcontentloaded' });

    // Two distinct waits so we can attribute time:
    //   - serverConnected: WS handshake + auth roundtrip done
    //   - sidebar item visible: drive resource + child collection populated
    await page.waitForFunction(
      () => window.store?.getSyncStatus().serverConnected === true,
      undefined,
      { timeout: 15000 },
    );
    const wsConnectedMs = Date.now() - reloadStart;

    await expect(
      page.getByTestId('sidebar').getByText('Perf Probe Doc'),
    ).toBeVisible({ timeout: 15000 });
    const sidebarVisibleMs = Date.now() - reloadStart;

    // eslint-disable-next-line no-console
    console.log(
      `[perf] reload→serverConnected = ${wsConnectedMs}ms,` +
        ` reload→sidebar = ${sidebarVisibleMs}ms`,
    );

    await attachPerfSnapshot(page, testInfo, 'perf-sidebar-after-reload');

    // Smoke assertion so the test passes; the real value is in the
    // captured trace.
    expect(sidebarVisibleMs).toBeLessThan(15000);
  });
});
