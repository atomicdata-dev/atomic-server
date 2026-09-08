/**
 * Scenario: offline-created drive must survive disabling localDB after sync.
 *
 * 1. Set up an agent + server-backed drive (dev-drive flow).
 * 2. Disconnect (offline).
 * 3. Create a second drive while offline — stored only in the WASM DB/OPFS,
 *    queued for sync via `dirtyForSync`.
 * 4. Reconnect (online). The store's `syncDirtyResources()` should push the
 *    offline-created drive to the server.
 * 5. Verify the server actually has it (HTTP GET against the drive subject).
 * 6. Disable the local WASM DB (`atomic-disable-client-db` in localStorage).
 * 7. Reload.
 * 8. Expect: the drive still loads (from the server).
 *
 * If step 8 fails, the offline-create → online-sync path is broken: the
 * drive exists in OPFS but never got to the server, so disabling the local
 * layer "loses" it.
 */

import { test, expect } from './fixtures';
import { before, FRONTEND_URL, waitForSynced } from './test-utils';

test.describe('offline create → online sync → disable localDB', () => {
  test.beforeEach(before);

  test('offline-created drive loads after disabling localDB', async ({
    page,
  }) => {
    // Forward relevant browser-side logs so failures are diagnosable.
    page.on('console', msg => {
      const text = msg.text();

      if (
        text.startsWith('[Sync]') ||
        text.startsWith('[Store]') ||
        text.startsWith('[ClientDb]') ||
        text.startsWith('[offline-trace]')
      ) {
        console.log(`[browser-${msg.type()}]`, text);
      }
    });

    // 1. Wait for the initial dev-drive setup: clientDb ready + server connected.
    await page.waitForFunction(
      () => {
        return (
          window.store?.getClientDb()?.isReady === true &&
          window.store?.getSyncStatus().serverConnected === true
        );
      },
      undefined,
      { timeout: 30000 },
    );

    // 2. Go offline.
    await page.evaluate(() => {
      window.store.disconnect();
    });
    await page.waitForFunction(
      () => window.store?.getSyncStatus().serverConnected === false,
      undefined,
      { timeout: 15000 },
    );

    // 3. Create a drive while offline.
    const offlineDriveSubject = await page.evaluate(async () => {
      const store = window.store;
      const drive = await store.createDrive('Offline-Created Drive', {
        description: 'Created while offline — must survive disabling localDB.',
        // An ADDITIONAL drive. `personal` defaults to true, and a personal
        // drive is now the agent's derived home — one subject per key — so
        // without this the call returns the dev drive this test already has
        // instead of creating anything.
        personal: false,
      });

      return drive.subject as string;
    });
    console.log(`[setup] offline-created drive: ${offlineDriveSubject}`);
    expect(offlineDriveSubject).toMatch(/^did:ad:/);

    // Confirm it's in the dirty queue (waiting to be synced).
    const pendingBeforeReconnect = await page.evaluate(
      () => window.store.getSyncStatus().pendingDirtyCount,
    );
    console.log(
      `[setup] pendingDirtyCount while offline: ${pendingBeforeReconnect}`,
    );
    expect(pendingBeforeReconnect).toBeGreaterThan(0);

    // 4. Reconnect and wait for the dirty sync to drain.
    // Four genesis commits after a WS handshake routinely exceeds 15s under
    // dagger load; `waitForSynced` is 30s and dumps the outbox on timeout.
    await page.evaluate(() => {
      window.store.reconnect();
    });
    await page.waitForFunction(
      () => window.store?.getSyncStatus().serverConnected === true,
      undefined,
      { timeout: 15_000 },
    );
    await waitForSynced(page);
    console.log('[setup] dirty queue drained');

    // 5. Verify the server actually has the offline-created drive.
    // Drives have DID subjects — the server exposes them at `/{did-subject}`
    // but DIDs aren't fetchable as URLs directly; use the store's live
    // Client to fetch once more and confirm the server returned a real object.
    const serverHas = await page.evaluate(async (subject: string) => {
      try {
        const res = await window.store.fetchResourceFromServer(subject);

        return {
          fetched: true,
          hasName: !!res?.get?.('https://atomicdata.dev/properties/name'),
        };
      } catch (e) {
        return { fetched: false, error: e?.message };
      }
    }, offlineDriveSubject);
    console.log('[setup] server-has check:', JSON.stringify(serverHas));
    expect(serverHas.fetched).toBe(true);

    // 6. Make the offline-created drive the active one, then disable localDB.
    await page.evaluate((subject: string) => {
      window.store.setDrive(subject);
      // Disable client DB — same mechanism SyncRoute uses.
      localStorage.setItem('atomic-disable-client-db', '1');
    }, offlineDriveSubject);

    // Navigate to the drive's page so the route's useResource(drive) fires.
    await page.goto(
      `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(offlineDriveSubject)}`,
    );

    // 8. Verify the drive auto-loads (the route's useResource, not an explicit
    // fetch). The real bug we are hunting is a resource stub that goes to
    // loading=false without props being populated.
    await page
      .waitForFunction(
        () => {
          if (!window.store?.getSyncStatus().serverConnected) {
            return false;
          }

          const drive = window.store.getSyncStatus().drive;

          if (!drive) {
            return false;
          }

          const r = window.store.resources.get(drive);

          return (
            r &&
            !r.loading &&
            !r.error &&
            !!r.get('https://atomicdata.dev/properties/name')
          );
        },
        undefined,
        // 30s. With ClientDb disabled, fetching the drive goes server-only
        // over a fresh WS handshake on each reload (init store → resolve
        // agent from IDB → open WS → SYNC_VV handshake → first GET).
        { timeout: 30000 },
      )
      .catch(() => {
        /* surface via the assertions below instead of throwing here */
      });

    const finalState = await page.evaluate(() => {
      const status = window.store.getSyncStatus();
      const drive = status.drive!;
      const r = window.store.resources.get(drive);
      const props: Record<string, unknown> = {};

      if (r) {
        for (const [k, v] of r.getEntries()) {
          props[k] =
            v instanceof Uint8Array ? `<Uint8Array ${v.byteLength}b>` : v;
        }
      }

      return {
        drive,
        serverConnected: status.serverConnected,
        clientDbAttached: status.clientDbAttached,
        loading: r?.loading,
        error: r?.error?.message,
        name: r?.get('https://atomicdata.dev/properties/name'),
        props,
      };
    });
    console.log('[final]', JSON.stringify(finalState, null, 2));

    expect(finalState.drive).toBe(offlineDriveSubject);
    expect(finalState.clientDbAttached).toBe(false); // localDB disabled
    expect(finalState.loading).toBeFalsy();
    expect(finalState.error).toBeFalsy();
    expect(finalState.name).toBe('Offline-Created Drive');

    // Cleanup: re-enable localDB so subsequent tests start clean.
    await page.evaluate(() =>
      localStorage.removeItem('atomic-disable-client-db'),
    );
  });
});
