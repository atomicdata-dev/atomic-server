import { test, expect } from './fixtures';
import { devDrive } from './test-utils';

// Regression for the ClientDb edit-persistence fix (store.ts drain re-persist):
// a local edit must reach OPFS, not just the server, so a reload reflects it.
// Before the fix `editNameLocal` stayed at the pre-edit value.
test('edit persists to local ClientDb across the drain', async ({ page }) => {
  await devDrive(page);

  const result = await page.evaluate(async () => {
    const s = window.store;
    const drive =
      document.querySelector('main[about]')?.getAttribute('about') ?? undefined;
    const NAME = 'https://atomicdata.dev/properties/name';
    const FOLDER = 'https://atomicdata.dev/classes/Folder';

    // `fetchResourceFromClientDb` is a private Store method reached here only
    // to probe local persistence from inside the page; cast to bypass TS's
    // visibility check (this runs as plain JS in the browser).
    const asAny = s as unknown as {
      fetchResourceFromClientDb: (
        subject: string,
      ) => Promise<{ get?: (prop: string) => unknown } | undefined>;
    };

    const tmp = await s.createSubject('persist-test');
    const r = await s.newResource({ subject: tmp, parent: drive, isA: FOLDER });
    await r.set(NAME, 'PersistProbe-A');
    await r.save();
    const realSubject = r.subject;
    const db = s.getClientDb();

    if (!db) {
      throw new Error('ClientDb missing — cannot probe OPFS persistence');
    }

    // Writes commit with Durability::None; flush() is the durable signal.
    await db.flush();
    const afterCreate = await asAny.fetchResourceFromClientDb(realSubject);

    const r2 = await s.getResource(realSubject);
    await r2.set(NAME, 'PersistProbe-B-EDITED');
    await r2.save();
    await db.flush();
    const afterEdit = await asAny.fetchResourceFromClientDb(realSubject);
    const srv = await s.fetchResourceFromServer(realSubject);

    return {
      createName: afterCreate?.get?.(NAME),
      editNameLocal: afterEdit?.get?.(NAME),
      editNameServer: srv?.get?.(NAME),
    };
  });

  expect(result.createName).toBe('PersistProbe-A');
  expect(result.editNameServer).toBe('PersistProbe-B-EDITED');
  expect(result.editNameLocal).toBe('PersistProbe-B-EDITED');
});
