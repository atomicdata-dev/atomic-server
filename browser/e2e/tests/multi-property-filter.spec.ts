import { test, expect } from './fixtures';
import { before } from './test-utils';

/**
 * Full-stack regression for multi-property (AND) filtering.
 *
 * A `QueryFilter` can hold extra `(property, value)` constraints beyond the
 * primary `property`/`value`, combined with **AND**. This exercises both
 * query backends the running app uses:
 *
 *   - the local WASM/OPFS DB (`store.queryLocalDb`, the same call
 *     `Collection.fetchPageFromLocalDb` makes), and
 *   - the server `/query` endpoint (the same URL `Collection.buildSubject`
 *     builds, with the extra constraints in a `filters` JSON param).
 *
 * Setup: three folders on the drive —
 *   A: name = grp-shared, description = match-AAA   ← matches BOTH
 *   B: name = grp-shared, description = other-BBB   ← matches name only
 *   C: name = grp-other,  description = match-AAA   ← matches description only
 *
 * Filter `name = grp-shared AND description = match-AAA` must return ONLY A.
 */

const NAME = 'https://atomicdata.dev/properties/name';
const DESCRIPTION = 'https://atomicdata.dev/properties/description';
const FOLDER = 'https://atomicdata.dev/classes/Folder';

test.describe('multi-property (AND) filtering', () => {
  test.beforeEach(before);

  test('filtering on two properties returns only the resource matching both', async ({
    page,
  }) => {
    // Wait until the local DB is ready so created resources land in OPFS.
    await page.waitForFunction(
      () =>
        window.store?.getClientDb()?.isReady === true &&
        window.store?.getSyncStatus().serverConnected === true,
      undefined,
      { timeout: 30000 },
    );

    // Create the three folders programmatically through the store.
    const created = await page.evaluate(
      async ({ nameProp, descProp, folder }) => {
        const store = window.store;
        const drive = store.getDrive();

        const make = async (name: string, description: string) => {
          const r = await store.newResource({
            parent: drive,
            isA: folder,
            propVals: { [nameProp]: name, [descProp]: description },
          });
          await r.save();

          return r.subject;
        };

        const a = await make('grp-shared', 'match-AAA');
        const b = await make('grp-shared', 'other-BBB');
        const c = await make('grp-other', 'match-AAA');

        return { drive, a, b, c };
      },
      { nameProp: NAME, descProp: DESCRIPTION, folder: FOLDER },
    );

    // Wait for everything to sync (server index) and OPFS to settle.
    await page.waitForFunction(
      () => window.store?.getSyncStatus().pendingDirtyCount === 0,
      undefined,
      { timeout: 30000 },
    );

    // Sanity: the single-property query (name = grp-shared) sees A and B in
    // the local DB — confirms the resources are indexed before we assert the
    // narrower AND result.
    await page.waitForFunction(
      async ([nameProp, drive, a, b]) => {
        const res = await window.store.queryLocalDb({
          property: nameProp,
          value: 'grp-shared',
          drive,
        });

        const subjects = res?.subjects ?? [];

        return subjects.includes(a) && subjects.includes(b);
      },
      [NAME, created.drive, created.a, created.b] as const,
      { timeout: 30000, polling: 500 },
    );

    // --- Local WASM/OPFS DB path ---
    const localSubjects = await page.evaluate(
      async ({ nameProp, descProp, drive }) => {
        const res = await window.store.queryLocalDb({
          property: nameProp,
          value: 'grp-shared',
          filters: [{ property: descProp, value: 'match-AAA' }],
          drive,
        });

        return res?.subjects ?? [];
      },
      { nameProp: NAME, descProp: DESCRIPTION, drive: created.drive! },
    );

    expect(
      localSubjects,
      'Local WASM DB AND-filter (name=grp-shared AND description=match-AAA) ' +
        'must return only folder A',
    ).toEqual([created.a]);

    // --- Server /query path ---
    const serverMembers = await page.evaluate(
      async ({ nameProp, descProp, drive }) => {
        const store = window.store;
        const url = new URL(`${store.getServerUrl()}/query`);
        url.searchParams.set('property', nameProp);
        url.searchParams.set('value', 'grp-shared');
        url.searchParams.set(
          'filters',
          JSON.stringify([{ property: descProp, value: 'match-AAA' }]),
        );
        url.searchParams.set('drive', drive);

        const res = await store.fetchResourceFromServer(url.toString());
        const members = res?.get(
          'https://atomicdata.dev/properties/collection/members',
        );

        return Array.isArray(members) ? (members as string[]) : [];
      },
      { nameProp: NAME, descProp: DESCRIPTION, drive: created.drive! },
    );

    expect(
      serverMembers,
      'Server /query AND-filter must return only folder A',
    ).toEqual([created.a]);
  });

  test('operator filters (starts_with / contains) agree on local and server paths', async ({
    page,
  }) => {
    await page.waitForFunction(
      () =>
        window.store?.getClientDb()?.isReady === true &&
        window.store?.getSyncStatus().serverConnected === true,
      undefined,
      { timeout: 30000 },
    );

    // Three folders under the drive; filter on `name` with operators.
    const created = await page.evaluate(
      async ({ nameProp, folder }) => {
        const store = window.store;
        const drive = store.getDrive();

        const make = async (name: string) => {
          const r = await store.newResource({
            parent: drive,
            isA: folder,
            propVals: { [nameProp]: name },
          });
          await r.save();

          return r.subject;
        };

        const apple = await make('Apple');
        const apricot = await make('Apricot');
        const banana = await make('Banana');

        return { drive, apple, apricot, banana };
      },
      { nameProp: NAME, folder: FOLDER },
    );

    await page.waitForFunction(
      () => window.store?.getSyncStatus().pendingDirtyCount === 0,
      undefined,
      { timeout: 30000 },
    );

    const PARENT = 'https://atomicdata.dev/properties/parent';
    const sorted = (xs: string[]) => [...xs].sort();

    // Wait until the local DB sees all three children (indexed) before asserting.
    await page.waitForFunction(
      async ([nameProp, drive, ...subjects]) => {
        const res = await window.store.queryLocalDb({
          property: nameProp,
          value: 'Apple',
          drive,
        });

        return (res?.subjects ?? []).includes(subjects[0]);
      },
      [NAME, created.drive, created.apple] as const,
      { timeout: 30000, polling: 500 },
    );

    // --- Local WASM/OPFS path: name starts_with "Ap" → Apple + Apricot ---
    const localStarts = await page.evaluate(
      async ({ parent, nameProp, drive }) => {
        const res = await window.store.queryLocalDb({
          property: parent,
          value: drive,
          filters: [
            { property: nameProp, value: 'Ap', operator: 'starts_with' },
          ],
          drive,
        });

        return res?.subjects ?? [];
      },
      { parent: PARENT, nameProp: NAME, drive: created.drive! },
    );

    expect(sorted(localStarts), 'local starts_with "Ap"').toEqual(
      sorted([created.apple, created.apricot]),
    );

    // --- Server /query path: name contains "an" → Banana ---
    const serverContains = await page.evaluate(
      async ({ parent, nameProp, drive }) => {
        const store = window.store;
        const url = new URL(`${store.getServerUrl()}/query`);
        url.searchParams.set('property', parent);
        url.searchParams.set('value', drive);
        url.searchParams.set(
          'filters',
          JSON.stringify([
            { property: nameProp, value: 'an', operator: 'contains' },
          ]),
        );
        url.searchParams.set('drive', drive);

        const res = await store.fetchResourceFromServer(url.toString());
        const members = res?.get(
          'https://atomicdata.dev/properties/collection/members',
        );

        return Array.isArray(members) ? (members as string[]) : [];
      },
      { parent: PARENT, nameProp: NAME, drive: created.drive! },
    );

    expect(serverContains, 'server contains "an"').toEqual([created.banana]);
  });
});
