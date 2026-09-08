import { test, expect } from './fixtures';
import { before, FRONTEND_URL } from './test-utils';

/**
 * Self-hosted plain-HTTP deployments (e.g. http://homeassistant.local:9883)
 * are *insecure contexts*: the browser withholds the Web Locks + OPFS APIs the
 * local ClientDb needs. The app must fall back to a server-only mode and stay
 * functional — create a resource, refresh, it's still there (fetched from the
 * server). Simulated here by removing `navigator.locks`, which is exactly what
 * an insecure context does and what trips the ClientDb's degraded path.
 */
test.describe('server-only fallback (no OPFS / Web Locks)', () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      try {
        Object.defineProperty(navigator, 'locks', {
          value: undefined,
          configurable: true,
        });
      } catch {
        /* ignore */
      }
    });
  });

  test('create drive + resource survives a refresh without the local DB', async ({
    page,
  }) => {
    await before({ page }); // devDrive — creates an agent + drive on the server

    const ids = await page.evaluate(async () => {
      const s = window.store;
      const NAME = 'https://atomicdata.dev/properties/name';
      const FOLDER = 'https://atomicdata.dev/classes/Folder';
      const drive = s.getDrive();

      if (!drive) throw new Error('no active drive');

      const tmp = await s.createSubject('fb');
      const f = await s.newResource({
        subject: tmp,
        parent: drive,
        isA: FOLDER,
      });
      await f.set(NAME, 'FallbackFolder', false);
      await f.save();

      return { drive, folder: f.subject };
    });

    // Sanity: the local DB really is in degraded (server-only) mode. This is
    // false if `navigator.locks` weren't removed — i.e. the test genuinely
    // exercises the fallback, and fails if the ClientDb throws instead of
    // degrading cleanly.
    const degraded = await page.evaluate(() =>
      Boolean(window.store.getClientDb()?.initError),
    );
    expect(degraded).toBe(true);

    // The drive itself survives a refresh (its name resolves, not the bare DID).
    await page.goto(
      `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(ids.drive)}`,
    );
    await expect(page.getByText('Dev drive').first()).toBeVisible({
      timeout: 12000,
    });

    // The created resource survives a refresh (fetched from the server).
    await page.goto(
      `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(ids.folder)}`,
    );
    await expect(page.getByText('FallbackFolder').first()).toBeVisible({
      timeout: 12000,
    });

    // And it shows up in the drive's collection (file list) — the path that
    // must fall back from the local index to the server `/query`.
    await page.goto(
      `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(ids.drive)}`,
    );
    await expect(page.getByText('FallbackFolder').first()).toBeVisible({
      timeout: 12000,
    });
  });
});
