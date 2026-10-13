import { describe, it, vi, expect as assert } from 'vitest';
import { Collection } from './collection.js';
import type { ClientDbQueryResult, ClientDbWorker } from './client-db.js';
import { commits, core, dataBrowser, collections } from './index.js';
import { Resource } from './resource.js';
import { Store, StoreEvents } from './store.js';

/**
 * Opening a filled table (and the sidebar tree) flashed as if order changed.
 *
 * WASM `parent=` queries are unsorted. `fetchPageFromLocalDb` hydrates each
 * member into the store — each hydrate notifies `ResourceUpdated` — and
 * `useCollection` optimistic-adds those members in arrival order while
 * `pages.has(0)` is still false. Client-side sort then `setPage`s the real
 * order. The grid keeps the last-known subject by index, so index 0 briefly
 * shows the wrong row.
 *
 * The same listener is what `useChildren` uses for the sidebar, so folder
 * children flash the same way.
 */
const TABLE = 'atomic:resource:table';
const ALICE = 'atomic:resource:alice';
const BOB = 'atomic:resource:bob';
const CHARLIE = 'atomic:resource:charlie';
const DRIVE = 'atomic:resource:drive';

function jsonAd(
  subject: string,
  createdAt: number,
  sortOrder?: number,
): string {
  return JSON.stringify({
    '@id': subject,
    [core.properties.parent]: TABLE,
    [core.properties.isA]: [dataBrowser.classes.folder],
    [core.properties.name]: subject.slice('atomic:resource:'.length),
    [commits.properties.createdAt]: createdAt,
    ...(sortOrder !== undefined
      ? { [dataBrowser.properties.sortOrder]: sortOrder }
      : {}),
  });
}

function mockClientDb(
  query: () => Promise<ClientDbQueryResult>,
): ClientDbWorker {
  return {
    isReady: true,
    waitForReady: async () => true,
    query,
    flush: async () => undefined,
    putResourceWithSnapshot: async () => undefined,
    removeResource: async () => undefined,
  } as unknown as ClientDbWorker;
}

function pageMembers(collection: Collection): string[] {
  const pages = (
    collection as unknown as {
      pages: Map<number, Resource>;
    }
  ).pages;
  const page = pages.get(0);

  if (!page) return [];

  return page.getSubjects(collections.properties.members);
}

function wireLiveMembership(store: Store, collection: Collection): () => void {
  return store.on(StoreEvents.ResourceUpdated, resource => {
    collection.applyResourceChange(resource.subject, resource);
  });
}

describe('collection page assemble does not flash unsorted members', () => {
  it('requeries computed filters instead of admitting a row on stored properties alone', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    const collection = new Collection(
      store,
      'https://example.com',
      {
        page_size: '30',
        include_nested: false,
        property: core.properties.parent,
        value: TABLE,
        expression_filters: [
          {
            expression: { kind: 'difference', from: 0, to: 10 },
            operator: 'gte',
            value: 100,
          },
        ],
      },
      true,
    );
    const resource = new Resource(ALICE);
    resource.setStore(store);
    await resource.set(core.properties.parent, TABLE, false);
    expect(collection.applyResourceChange(ALICE, resource)).toBe(
      'membership-stale',
    );
    expect(pageMembers(collection)).toEqual([]);
  });

  it('does not optimistic-add hydrated members in query-arrival order', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    store.setDrive(DRIVE);
    store.finishDriveSync(DRIVE, 3, Date.now());

    // Index order is reverse of createdAt — the flash is this list showing
    // up as page 0 before the client-side sort lands.
    const unsorted: ClientDbQueryResult = {
      subjects: [CHARLIE, ALICE, BOB],
      resources: [
        jsonAd(CHARLIE, 3000),
        jsonAd(ALICE, 1000),
        jsonAd(BOB, 2000),
      ],
      count: 3,
    };

    store.setClientDb(mockClientDb(async () => unsorted));

    const collection = new Collection(
      store,
      'https://example.com',
      {
        page_size: '30',
        include_nested: false,
        property: core.properties.parent,
        value: TABLE,
        sort_by: commits.properties.createdAt,
        sort_desc: false,
        drive: DRIVE,
      },
      true,
    );

    const snapshots: string[][] = [];
    const unsub = wireLiveMembership(store, collection);
    const unsubSnap = store.on(StoreEvents.ResourceUpdated, () => {
      const members = pageMembers(collection);

      if (members.length > 0) snapshots.push([...members]);
    });

    await collection.refresh();
    unsub();
    unsubSnap();

    const sorted = [ALICE, BOB, CHARLIE];

    expect(await collection.getMembersOnPage(0)).toEqual(sorted);

    // Every observed page must already be in sort order. The regression
    // painted [CHARLIE] then [CHARLIE, ALICE] then the full reverse list
    // before `setPage` replaced it.
    for (const snap of snapshots) {
      expect(snap).toEqual(sorted.slice(0, snap.length));
    }
  });

  it('reads a bounded number of sort keys while a big list arrives', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    const collection = new Collection(
      store,
      'https://example.com',
      {
        page_size: '1000',
        include_nested: false,
        property: core.properties.parent,
        value: TABLE,
        sort_by: dataBrowser.properties.sortOrder,
        sort_desc: false,
      },
      true,
    );
    const reads = vi.spyOn(Resource.prototype, 'get');
    const n = 300;

    for (let i = 0; i < n; i++) {
      const subject = `https://example.com/row-${i}`;
      const row = new Resource(subject);
      row.applyHydratedValues([
        [core.properties.parent, TABLE],
        [core.properties.isA, [dataBrowser.classes.folder]],
        [commits.properties.createdAt, 1000 + i],
        [dataBrowser.properties.sortOrder, i],
      ]);
      row.loading = false;
      store.addResource(row);
      collection.applyResourceChange(subject, row);
    }

    const sortReads = reads.mock.calls.filter(
      ([prop]) => prop === dataBrowser.properties.sortOrder,
    ).length;

    reads.mockRestore();

    expect(pageMembers(collection)).toHaveLength(n);
    // Each arrival compares against the last member, not the whole list.
    expect(sortReads).toBeLessThan(n * 6);
  });

  it('files a late-arriving member in its sortOrder place, not at the end', async ({
    expect,
  }) => {
    // A reload whose local database held only the newest row: the page starts
    // with that row and the rest arrive after it.
    const store = new Store({ serverUrl: 'https://example.com' });
    const collection = new Collection(
      store,
      'https://example.com',
      {
        page_size: '30',
        include_nested: false,
        property: core.properties.parent,
        value: TABLE,
        sort_by: dataBrowser.properties.sortOrder,
        sort_desc: false,
      },
      true,
    );

    const arrive = (subject: string, createdAt: number, sortOrder: number) => {
      const row = new Resource(subject);
      row.applyHydratedValues([
        [core.properties.parent, TABLE],
        [core.properties.isA, [dataBrowser.classes.folder]],
        [commits.properties.createdAt, createdAt],
        [dataBrowser.properties.sortOrder, sortOrder],
      ]);
      row.loading = false;
      store.addResource(row);
      collection.applyResourceChange(subject, row);
    };

    // Created a second after the others, positioned between them.
    arrive(CHARLIE, 3000, 1500);
    arrive(ALICE, 1000, 1000);
    arrive(BOB, 2000, 2000);

    expect(pageMembers(collection)).toEqual([ALICE, CHARLIE, BOB]);
  });

  it('still optimistic-adds a resource created while the local query is in flight', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    store.setDrive(DRIVE);
    store.finishDriveSync(DRIVE, 3, Date.now());

    const created = 'atomic:resource:created-during-query';
    let releaseQuery!: () => void;
    const queryGate = new Promise<void>(resolve => {
      releaseQuery = resolve;
    });
    let queryEntered!: () => void;
    const queryEnteredP = new Promise<void>(resolve => {
      queryEntered = resolve;
    });

    store.setClientDb(
      mockClientDb(async () => {
        queryEntered();
        await queryGate;

        return {
          subjects: [ALICE, BOB],
          resources: [jsonAd(ALICE, 1000), jsonAd(BOB, 2000)],
          count: 2,
        };
      }),
    );

    const collection = new Collection(
      store,
      'https://example.com',
      {
        page_size: '30',
        include_nested: false,
        property: core.properties.parent,
        value: TABLE,
        sort_by: commits.properties.createdAt,
        sort_desc: false,
        drive: DRIVE,
      },
      true,
    );

    const unsub = wireLiveMembership(store, collection);
    const refresh = collection.refresh();
    await queryEnteredP;

    const draft = new Resource(created);
    draft.applyHydratedValues([
      [core.properties.parent, TABLE],
      [core.properties.isA, [dataBrowser.classes.folder]],
      [core.properties.name, 'Created during query'],
      [commits.properties.createdAt, 1500],
    ]);
    draft.loading = false;
    store.addResource(draft);

    expect(pageMembers(collection)).toEqual([created]);

    releaseQuery();
    await refresh;
    unsub();

    const members = await collection.getMembersOnPage(0);
    expect(members.slice(0, 2)).toEqual([ALICE, BOB]);
    expect(members).toContain(created);
  });

  it.each([false, true])(
    'does not restore a deleted member from an in-flight query (optimistic=%s)',
    async optimistic => {
      const store = new Store({ serverUrl: 'https://example.com' });
      store.setDrive(DRIVE);
      store.finishDriveSync(DRIVE, 2, Date.now());
      const stale = {
        subjects: [ALICE, BOB],
        resources: [jsonAd(ALICE, 1000), jsonAd(BOB, 2000)],
        count: 2,
      };
      let release!: (result: ClientDbQueryResult) => void;
      let delayed = false;
      store.setClientDb(
        mockClientDb(async () =>
          delayed
            ? new Promise(resolve => {
                release = resolve;
              })
            : stale,
        ),
      );
      const collection = new Collection(
        store,
        'https://example.com',
        {
          page_size: '30',
          include_nested: false,
          property: core.properties.parent,
          value: TABLE,
          drive: DRIVE,
        },
        true,
      );
      await collection.refresh();

      if (optimistic) {
        // A member that leaves the filter and comes back before any destroy.
        collection.applyResourceChange(ALICE, undefined);
        collection.applyResourceChange(ALICE, store.resources.get(ALICE));
      }

      delayed = true;
      const refreshing = collection.refresh();
      await new Promise(resolve => setTimeout(resolve, 0));
      // The destroy. `useCollection` mirrors it onto the collection from the
      // `ResourceRemoved` event; the fact itself lives on the store.
      store.removeResource(ALICE);
      collection.applyResourceChange(ALICE, undefined);
      const hydrate = vi.spyOn(store, 'hydrateResourceFromJsonAd');
      release(stale);
      await refreshing;
      assert(await collection.getMembersOnPage(0)).toEqual([BOB]);
      assert(collection.totalMembers).toBe(1);
      assert(hydrate.mock.calls.map(([subject]) => subject)).toEqual([BOB]);
      hydrate.mockRestore();

      // A resource event carrying the destroyed subject must NOT bring it
      // back — that event is the stale answer itself, arriving through the
      // store. This is what used to put the row back in the sidebar, where
      // rendering it re-created the entry the destroy had removed.
      const stillStale = new Resource(ALICE);
      stillStale.applyHydratedValues([
        [core.properties.parent, TABLE],
        [commits.properties.createdAt, 1000],
      ]);
      stillStale.loading = false;
      assert(collection.applyResourceChange(ALICE, stillStale)).toBe(
        'unchanged',
      );
      assert(await collection.getMembersOnPage(0)).toEqual([BOB]);
      assert(collection.totalMembers).toBe(1);

      // Only a genuine re-creation under the same subject lifts the
      // tombstone, and then the member is admitted again.
      store.clearDestroyed(ALICE);
      assert(collection.applyResourceChange(ALICE, stillStale)).toBe(
        'member-added',
      );
      assert(await collection.getMembersOnPage(0)).toEqual([BOB, ALICE]);
      assert(collection.totalMembers).toBe(2);
    },
  );

  it('builds only the requested page of a big table whose rows have no sortOrder', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    store.setDrive(DRIVE);
    store.finishDriveSync(DRIVE, 2, Date.now());

    const n = 300;
    // Newest first, as an index that does not know the order may answer.
    const subjects = Array.from(
      { length: n },
      (_, i) => `atomic:resource:row-${String(n - i).padStart(4, '0')}`,
    );
    store.setClientDb(
      mockClientDb(async () => ({
        subjects,
        resources: subjects.map(s => jsonAd(s, 1000 + Number(s.slice(-4)))),
        count: n,
      })),
    );

    const collection = new Collection(
      store,
      'https://example.com',
      {
        page_size: '30',
        include_nested: false,
        property: core.properties.parent,
        value: TABLE,
        sort_by: dataBrowser.properties.sortOrder,
        sort_desc: false,
      },
      true,
    );
    const hydrate = vi.spyOn(store, 'hydrateResourceFromJsonAd');

    const page = await collection.getMembersOnPage(0);

    // Oldest first, and only the 30 rows on the page were built.
    expect(page[0]).toBe('atomic:resource:row-0001');
    expect(page).toHaveLength(30);
    expect(hydrate.mock.calls.length).toBeLessThanOrEqual(30);
    hydrate.mockRestore();
  });

  it('treats a missing sort key as missing, not the string "undefined"', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    store.setDrive(DRIVE);
    store.finishDriveSync(DRIVE, 2, Date.now());

    store.setClientDb(
      mockClientDb(async () => ({
        subjects: [ALICE, BOB],
        resources: [
          JSON.stringify({
            '@id': ALICE,
            [core.properties.parent]: TABLE,
            [core.properties.isA]: [dataBrowser.classes.folder],
          }),
          JSON.stringify({
            '@id': BOB,
            [core.properties.parent]: TABLE,
            [core.properties.isA]: [dataBrowser.classes.folder],
            // Sorts before the string "undefined", so a stringify-the-missing
            // bug would put Bob first. Missing-first (server TAG_NONE) puts
            // Alice first.
            [core.properties.name]: 'aardvark',
          }),
        ],
        count: 2,
      })),
    );

    const collection = new Collection(
      store,
      'https://example.com',
      {
        page_size: '30',
        include_nested: false,
        property: core.properties.parent,
        value: TABLE,
        sort_by: core.properties.name,
        sort_desc: false,
        drive: DRIVE,
      },
      true,
    );

    await collection.refresh();

    expect(await collection.getMembersOnPage(0)).toEqual([ALICE, BOB]);
  });
});

describe('deferred collection membership', () => {
  it('shares one fetch between concurrent reads from the same missing page', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    store.setDrive(DRIVE);
    const subjects = Array.from(
      { length: 40 },
      (_, i) => `atomic:resource:row-${i}`,
    );
    let queryCount = 0;
    store.setClientDb(
      mockClientDb(async () => {
        queryCount += 1;

        return {
          subjects,
          count: subjects.length,
          resources: subjects.map((s, i) => jsonAd(s, i)),
        };
      }),
    );
    const collection = new Collection(
      store,
      'https://example.com',
      {
        page_size: '30',
        include_nested: false,
        property: core.properties.parent,
        value: TABLE,
      },
      true,
    );

    await collection.refresh();
    const secondPage = await Promise.all(
      Array.from({ length: 10 }, (_, i) =>
        collection.getMemberWithIndex(30 + i),
      ),
    );

    expect(secondPage).toEqual(subjects.slice(30));
    expect(queryCount).toBe(2);
  });

  it('does not count later pages again when hydration notifications are deferred', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    store.setDrive(DRIVE);
    const subjects = Array.from(
      { length: 90 },
      (_, i) => `atomic:resource:row-${i}`,
    );
    store.setClientDb(
      mockClientDb(async () => ({
        subjects,
        count: 90,
        resources: subjects.map((s, i) => jsonAd(s, i)),
      })),
    );
    const collection = new Collection(
      store,
      'https://example.com',
      {
        page_size: '30',
        include_nested: false,
        property: core.properties.parent,
        value: TABLE,
      },
      true,
    );
    const unsubscribe = store.on(StoreEvents.ResourceUpdated, resource => {
      queueMicrotask(() =>
        collection.applyResourceChange(resource.subject, resource),
      );
    });

    // Another collection can announce these records before this query resolves.
    for (const subject of subjects.slice(30)) {
      const resource = new Resource(subject);
      resource.applyHydratedValues([[core.properties.parent, TABLE]]);
      resource.loading = false;
      collection.applyResourceChange(subject, resource);
    }

    await collection.refresh();
    await Promise.resolve();
    expect(collection.totalMembers).toBe(90);
    expect(await collection.getMemberWithIndex(89)).toBeDefined();
    unsubscribe();
  });
});
