import { test, expect } from './fixtures';
import {
  before,
  FRONTEND_URL,
  waitForClientDbFlush,
  waitForServerConnected,
  waitForSynced,
} from './test-utils';

/**
 * Repro for: open a DID folder's own page, refresh → it renders BROKEN (raw
 * subject as H1, no Folder view, no isA), even though the server has the full
 * resource (the Data page's `/did?subject=` fetch returns complete JSON-AD).
 *
 * The createdBy/createdAt subtitle that shows in the broken view is derived
 * from the DID genesis, so a resource with ZERO real props still renders that
 * line — the tell that the store hydrated only genesis metadata, never the
 * actual properties.
 */
test('DID folder page survives a reload', async ({ page }) => {
  await before({ page }); // devDrive

  const folder = await page.evaluate(async () => {
    const s = window.store;
    const d = s.getDrive();

    if (!d) throw new Error('no drive');

    const tmp = await s.createSubject('fld');
    const f = await s.newResource({
      subject: tmp,
      parent: d,
      isA: 'https://atomicdata.dev/classes/Folder',
    });
    await f.set(
      'https://atomicdata.dev/properties/name',
      'ReloadFolder',
      false,
    );
    await f.save();

    return f.subject;
  });

  // Open the folder's OWN page (not the drive page) and let it render.
  await page.goto(
    `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(folder)}`,
  );
  await expect(page.getByRole('heading', { name: 'ReloadFolder' })).toBeVisible(
    {
      timeout: 15000,
    },
  );

  // Give the OPFS flush tick time, then turn OFF Local DB (the Sync-page
  // toggle the user used) so the reload must hydrate the folder purely from
  // the server — exercising the DID server-fetch path.
  await waitForSynced(page);
  await waitForClientDbFlush(page);
  await page.evaluate(() =>
    localStorage.setItem('atomic-disable-client-db', '1'),
  );
  await page.reload();

  // Wait for the WS to reconnect after reload, then wait until the store
  // actually holds the folder's name — not a 500ms poll hoping it landed.
  await waitForServerConnected(page);
  await page.waitForFunction(
    f => {
      const s = window.store;
      s?.getResource(f).catch(() => undefined);
      const r = s?.resources.get(f);

      return (
        r?.get?.('https://atomicdata.dev/properties/name') === 'ReloadFolder'
      );
    },
    folder,
    { timeout: 12_000 },
  );
  const diag = await page.evaluate(f => {
    const s = window.store;
    const r = s.resources.get(f);

    return {
      present: !!r,
      entries: r?.getEntries ? r.getEntries().length : -1,
      isA: (r?.get?.('https://atomicdata.dev/properties/isA') ??
        null) as unknown,
      name: r?.get?.('https://atomicdata.dev/properties/name') ?? null,
      loading: r?.loading ?? null,
      error: r?.error?.message ?? null,
      serverConnected: s.getSyncStatus?.()?.serverConnected ?? null,
    };
  }, folder);
  console.log(
    '[did-folder-reload] post-reload store state:',
    JSON.stringify(diag),
  );

  // The folder must render as a folder: its name as the heading, NOT the raw
  // subject. This is the assertion that fails when the bug reproduces.
  await expect(page.getByRole('heading', { name: 'ReloadFolder' })).toBeVisible(
    {
      timeout: 15000,
    },
  );
});
