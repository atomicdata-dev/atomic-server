import { test, expect } from './fixtures';
import {
  before,
  newDrive,
  FRONTEND_URL,
  waitForClientDbFlush,
  waitForSynced,
} from './test-utils';

/**
 * The Sync page "Local DB" toggle writes `atomic-disable-client-db=1` to
 * localStorage; on the next load `App.tsx` skips `initClientDb`, so the store
 * has no ClientDb and EVERY read goes to the server (`fetchPageFromServer` /
 * `fetchResourceFromServer`). That server-only path was previously masked by
 * the OPFS cache, so a drive whose children the server `/query` won't return
 * looked fine with Local DB on and empty with it off.
 *
 * This reproduces the user's report ("turn off Local DB, reconnect, refresh →
 * drive shows no resources"): create a drive + a child with Local DB on, then
 * disable Local DB and reload. The child must still render — proving the
 * server actually has it and the server-only collection path surfaces it.
 */
test('drive contents load with Local DB disabled (server-only)', async ({
  page,
}) => {
  await before({ page }); // devDrive — fresh agent + drive, Local DB on
  const drive = await page.evaluate(async () => {
    const s = window.store;
    const d = s.getDrive();

    if (!d) throw new Error('no drive');

    const tmp = await s.createSubject('ldb');
    const f = await s.newResource({
      subject: tmp,
      parent: d,
      isA: 'https://atomicdata.dev/classes/Folder',
    });
    await f.set(
      'https://atomicdata.dev/properties/name',
      'LocalDbOffChild',
      false,
    );
    await f.save();

    return d;
  });

  // Persist the create, then disable Local DB so the reload hydrates from
  // the server only.
  await waitForSynced(page);
  await waitForClientDbFlush(page);

  // Toggle "Local DB" off (what the Sync page does) and reload. From here the
  // store never initialises ClientDb — the drive page is served purely from
  // the server.
  await page.evaluate(() =>
    localStorage.setItem('atomic-disable-client-db', '1'),
  );
  await page.goto(
    `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(drive)}`,
  );

  // Sanity: ClientDb really is absent (we're exercising the server-only path).
  await expect
    .poll(
      () => page.evaluate(() => !!window.store && !window.store.getClientDb()),
      {
        timeout: 10000,
      },
    )
    .toBe(true);

  await expect(page.getByText('LocalDbOffChild').first()).toBeVisible({
    timeout: 15000,
  });
});

/**
 * Same as above but for a drive created via the regular "New Drive" UI flow
 * (subdomain + dialog) rather than `/app/dev-drive`. The user's affected drive
 * was a real UI-created drive, so this is the closer repro — it checks that a
 * UI-created drive's `parent=<drive>` children survive the server-only path
 * (and so are indexed clean, with no `?drive=` hint mismatch on the DID).
 */
test('UI-created drive contents load with Local DB disabled', async ({
  page,
}) => {
  await before({ page });
  const { driveURL } = await newDrive(page);

  await page.evaluate(async d => {
    const s = window.store;
    const tmp = await s.createSubject('ldb2');
    const f = await s.newResource({
      subject: tmp,
      parent: d,
      isA: 'https://atomicdata.dev/classes/Folder',
    });
    await f.set(
      'https://atomicdata.dev/properties/name',
      'UiDriveOffChild',
      false,
    );
    await f.save();
  }, driveURL);

  await waitForSynced(page);
  await waitForClientDbFlush(page);

  await page.evaluate(() =>
    localStorage.setItem('atomic-disable-client-db', '1'),
  );
  await page.goto(
    `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(driveURL)}`,
  );

  await expect
    .poll(
      () => page.evaluate(() => !!window.store && !window.store.getClientDb()),
      {
        timeout: 10000,
      },
    )
    .toBe(true);

  await expect(page.getByText('UiDriveOffChild').first()).toBeVisible({
    timeout: 15000,
  });
});
