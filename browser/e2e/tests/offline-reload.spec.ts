/**
 * Reproduction: after creating a dev-drive, switching to offline mode, and
 * reloading the page, resources that ARE in OPFS should still be available.
 * Currently the drive shows "Offline: resource not available locally".
 *
 * This test prints [offline-trace] logs from the client so we can see which
 * stage of the lookup fails (OPFS returning null, hydrate returning false,
 * lookup throwing, etc.).
 */
import { test, expect } from './fixtures';
import { before } from './test-utils';

test.describe('offline reload', () => {
  test.beforeEach(before);

  test('drive is available offline after reload', async ({ page }) => {
    page.on('console', msg => {
      const text = msg.text();

      if (
        text.startsWith('[offline-trace]') ||
        text.startsWith('[opfs-put-trace]') ||
        text.startsWith('[Store]') ||
        text.startsWith('[ClientDb]')
      ) {
        console.log(`[browser-${msg.type()}]`, text);
      }
    });

    // Wait for the ClientDb to be ready (don't require pendingDirtyCount=0
    // — dev-drive may have persistent dirty state we don't care about here).
    await page.waitForFunction(
      () => window.store?.getClientDb()?.isReady === true,
      undefined,
      { timeout: 30000 },
    );
    // Wait for the drive to actually land in OPFS — this is what we're
    // about to assert on, so bind to it directly.
    await page.waitForFunction(
      async () => {
        const drive = window.store?.getSyncStatus().drive;
        if (!drive) return false;
        const clientDb = window.store?.getClientDb();
        const jsonAd = await clientDb?.getResource?.(drive);

        return !!jsonAd;
      },
      undefined,
      { timeout: 15000 },
    );

    // Capture the drive subject + confirm OPFS actually has it.
    const { subject, opfsHas } = await page.evaluate(async () => {
      const drive = window.store.getSyncStatus().drive!;
      const clientDb = window.store.getClientDb()!;
      const jsonAd = await clientDb.getResource(drive);

      return { subject: drive, opfsHas: !!jsonAd };
    });

    console.log(`[setup] drive subject: ${subject}`);
    console.log(`[setup] OPFS has drive JSON-AD: ${opfsHas}`);
    expect(opfsHas).toBe(true);

    // Switch to offline mode.
    await page.evaluate(() => {
      window.store.disconnect();
    });

    // Reload.
    await page.reload();

    // Wait for the drive resource lookup to settle (loaded or errored — we
    // log finalState below either way). Without this we sample mid-flight.
    await page.waitForFunction(
      () => {
        const drive = window.store?.getSyncStatus().drive;
        if (!drive) return false;
        const r = window.store?.resources.get(drive);

        return !!r && !r.loading;
      },
      undefined,
      { timeout: 15000 },
    );

    const finalState = await page.evaluate(async () => {
      const drive = window.store.getSyncStatus().drive!;
      const drivesResource = window.store.resources.get(drive);
      const problematic: Array<{
        subject: string;
        loading?: boolean;
        error?: string;
      }> = [];

      for (const [subj, r] of window.store.resources.entries()) {
        if (r.loading || r.error) {
          problematic.push({
            subject: subj.slice(0, 80),
            loading: r.loading,
            error: r.error?.message,
          });
        }
      }

      return {
        driveSubject: drive,
        driveLoading: drivesResource?.loading,
        driveError: drivesResource?.error?.message,
        serverConnected: window.store.getSyncStatus().serverConnected,
        clientDbReady: window.store.getClientDb()?.isReady,
        totalResources: window.store.resources.size,
        problematic,
      };
    });
    console.log('[final state]', JSON.stringify(finalState, null, 2));

    // Also capture any body text that says "Offline:" — i.e. an ErrorPage
    // rendered somewhere in the UI tree.
    const bodyText = await page.locator('body').innerText();
    const offlineErrors = bodyText
      .split('\n')
      .filter(l => l.includes('Offline:'));
    console.log('[ui offline errors]', offlineErrors);
  });
});
