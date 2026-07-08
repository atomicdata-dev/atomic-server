import { describe, it, vi, afterEach } from 'vitest';
import { Resource, Store, core, Core, Datatype } from './index.js';
import { bootstrapCoreVocab } from './test-vocab.js';
import { testStore } from './test-store.js';

describe('Store', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('does not notify mounted readers while another reader takes its first snapshot', async ({
    expect,
  }) => {
    const store = new Store();
    const changed = vi.fn();
    const subject = 'did:ad:snapshot-reader';
    store.subscribe(subject, changed);
    store.getResourceSnapshot(subject, { newResource: true });
    expect(changed).not.toHaveBeenCalled();
    await Promise.resolve();
    expect(changed).toHaveBeenCalledTimes(1);
  });

  it('gives an unsaved form a permanent subject before minting its attachment', async ({
    expect,
  }) => {
    const { store, posted } = await testStore();
    const drive = await store.createDrive('Home');
    store.setDrive(drive.subject);
    const parent = new Resource('_new:attachment-form', true);
    parent.setStore(store);
    store.addResource(parent);
    await parent.set(
      core.properties.isA,
      ['https://atomicdata.dev/classes/Folder'],
      false,
    );
    await parent.set(core.properties.parent, drive.subject, false);
    (store as unknown as { clientDb: unknown }).clientDb = {
      isReady: true,
      blake3Hash: async () => new Uint8Array(32),
      putBlob: async () => undefined,
      flush: async () => undefined,
      putResourceWithSnapshot: async () => undefined,
    };
    const [subject] = await store.uploadFiles(
      [new File(['hello'], 'hello.txt')],
      parent.subject,
    );
    const file = store.resources.get(subject)!;
    expect(parent.subject).toMatch(/^did:ad:/);
    expect(file.get(core.properties.parent)).toBe(parent.subject);
    expect(parent.new).toBe(true);
    expect(store.outbox.getEntry(file.subject)).toBeUndefined();
    expect(store.outbox.getEntry(parent.subject)).toBeUndefined();
    // The required field is filled only after the attachment has an identity.
    await parent.set('https://example.com/required-file', subject, false);
    await parent.save();
    const genesis = posted.find(
      commit => commit.subject === parent.subject && commit.isGenesis,
    )!;
    expect(genesis).toBeDefined();
    const snapshot = new Resource(parent.subject);
    snapshot.setStore(store);
    snapshot.importLoroUpdate(genesis.loroUpdate!);
    expect(snapshot.get('https://example.com/required-file')).toBe(subject);
    expect(
      posted.some(commit => commit.subject === subject && commit.isGenesis),
    ).toBe(true);
  });

  it('persists merged state when an older resource arrives after an acknowledged edit', async ({
    expect,
  }) => {
    const { store } = await testStore();
    const resource = await store.newResource({
      isA: core.classes.resource,
      propVals: { [core.properties.name]: 'Before' },
    });
    await resource.save();
    const older = new Resource(resource.subject);
    older.setStore(store);
    older.importLoroUpdate(
      resource.getLoroDoc()!.export({ mode: 'snapshot' }),
      true,
    );
    const putResourceWithSnapshot = vi.fn().mockResolvedValue(undefined);
    store.setClientDb({
      isReady: true,
      flush: async () => undefined,
      putResourceWithSnapshot,
    } as unknown as Parameters<Store['setClientDb']>[0]);
    await resource.set(core.properties.name, 'After', false);
    await resource.save();
    store.addResource(older, { skipCommitCompare: true });
    expect(
      store.resources.get(resource.subject)!.get(core.properties.name),
    ).toBe('After');
    expect(putResourceWithSnapshot).toHaveBeenCalled();
    const [, json, snapshot] = putResourceWithSnapshot.mock.calls.at(-1)!;
    expect(JSON.parse(json)[core.properties.name]).toBe('After');
    const persisted = new Resource(resource.subject);
    persisted.setStore(store);
    persisted.importLoroUpdate(snapshot, true);
    expect(persisted.get(core.properties.name)).toBe('After');
  });

  it.each(['snapshot', 'flush'])(
    'an acknowledged edit waits for local %s before save resolves',
    async stage => {
      const { expect } = await import('vitest');
      const { store } = await testStore();
      const drive = await store.createDrive('Home');
      store.setDrive(drive.subject);
      const resource = await store.newResource({
        isA: 'https://atomicdata.dev/classes/Folder',
        parent: drive.subject,
        propVals: { [core.properties.name]: 'Before' },
      });
      await resource.save();
      let release!: () => void;
      const pendingWrite = new Promise<void>(resolve => {
        release = resolve;
      });
      const putResourceWithSnapshot = vi.fn(() =>
        stage === 'snapshot' ? pendingWrite : Promise.resolve(),
      );
      const flush = vi.fn(() =>
        stage === 'flush' ? pendingWrite : Promise.resolve(),
      );
      store.setClientDb({
        isReady: true,
        flush,
        putResourceWithSnapshot,
      } as unknown as Parameters<Store['setClientDb']>[0]);
      await resource.set(core.properties.name, 'After', false);
      let finished = false;
      const saving = resource.save().then(() => {
        finished = true;
      });

      try {
        await vi.waitFor(() =>
          expect(
            stage === 'snapshot' ? putResourceWithSnapshot : flush,
          ).toHaveBeenCalled(),
        );
        // The server is already mocked as acknowledged; only the local write
        // remains blocked. Leaving now must not expose the pre-edit cache.
        await new Promise(resolve => setTimeout(resolve, 20));
        expect(finished).toBe(false);
      } finally {
        release();
        await saving;
      }

      expect(finished).toBe(true);
    },
  );

  it('does not write to a database in unsupported server-only mode', async ({
    expect,
  }) => {
    const store = new Store();
    const putResourceWithSnapshot = vi
      .fn()
      .mockRejectedValue(new Error('unsupported'));
    store.setClientDb({
      initError: new Error('unsupported'),
      unsupportedEnvironment: true,
      flush: async () => undefined,
      putResourceWithSnapshot,
    } as unknown as Parameters<Store['setClientDb']>[0]);
    const resource = new Resource('did:ad:server-only');
    resource.setStore(store);
    await resource.persistToClientDb();
    expect(putResourceWithSnapshot).not.toHaveBeenCalled();
  });

  it('waits for the replacement database after an identity detaches its worker', async ({
    expect,
  }) => {
    const store = new Store();
    store.expectClientDb();
    const database = { isReady: true } as unknown as Parameters<
      Store['setClientDb']
    >[0];
    store.setClientDb(database);
    store.setClientDb(undefined);
    expect(store.getClientDb()).toBeUndefined();
    let attached = false;
    const waiting = store.waitForClientDb(1000).then(value => {
      attached = value;
    });
    await Promise.resolve();
    expect(attached).toBe(false);
    store.setClientDb(database);
    await waiting;
    expect(attached).toBe(true);
  });

  it('does not finish persistence before an expected database attaches', async ({
    expect,
  }) => {
    const store = new Store();
    store.expectClientDb();
    const resource = new Resource('did:ad:waiting-for-database');
    resource.setStore(store);
    let finished = false;
    const persisted = resource.persistToClientDb().then(() => {
      finished = true;
    });
    await Promise.resolve();
    expect(finished).toBe(false);
    const putResourceWithSnapshot = vi.fn().mockResolvedValue(undefined);
    store.setClientDb({
      isReady: true,
      flush: async () => undefined,
      putResourceWithSnapshot,
    } as unknown as Parameters<Store['setClientDb']>[0]);
    await persisted;
    expect(putResourceWithSnapshot).toHaveBeenCalledWith(
      resource.subject,
      expect.any(String),
      undefined,
    );
  });

  it('clears the previous identity drive before sign-out authentication changes', async ({
    expect,
  }) => {
    const { store } = await testStore();
    store.setDrive('did:ad:old-private-drive');
    store.setAgent(undefined);
    expect(store.getDrive()).toBeUndefined();
  });

  it('creates a complete personal drive when a lookup left a loading placeholder', async ({
    expect,
  }) => {
    const { store } = await testStore();
    const subject = await store.privateDriveSubject();
    const placeholder = new Resource(subject);
    placeholder.loading = true;
    store.addResource(placeholder);
    const drive = await store.createDrive('Real home');
    expect(drive.get(core.properties.name)).toBe('Real home');
    expect(drive.get(core.properties.isA)).toContain(
      'https://atomicdata.dev/classes/Drive',
    );
    expect(drive.get(core.properties.read)).toContain(
      store.getAgent()!.subject,
    );
  });

  it('renders the populate value', async ({ expect }) => {
    const store = new Store();
    const subject = 'https://atomicdata.dev/test';
    const testval = 'Hi world';
    const newResource = new Resource(subject);
    await newResource.set(core.properties.description, testval, false);
    store.addResource(newResource);
    const gotResource = store.getResourceLoading(subject);
    const atomString = gotResource!
      .get(core.properties.description)!
      .toString();
    expect(atomString).to.equal(testval);
  });

  it('fetches a resource', async ({ expect }) => {
    const store = new Store({ serverUrl: 'https://atomicdata.dev' });
    // Hermetic: serve the resource from a mock instead of the live domain, so
    // the test exercises the fetch+parse path without depending on the network.
    store.injectFetch(
      async () =>
        new Response(
          JSON.stringify({
            '@id': 'https://atomicdata.dev/properties/createdAt',
            'https://atomicdata.dev/properties/shortname': 'created-at',
            'https://atomicdata.dev/properties/description':
              'When the resource was created.',
            'https://atomicdata.dev/properties/datatype':
              'https://atomicdata.dev/datatypes/timestamp',
            'https://atomicdata.dev/properties/isA': [
              'https://atomicdata.dev/classes/Property',
            ],
          }),
          { status: 200, headers: { 'content-type': 'application/ad+json' } },
        ),
    );
    const resource = await store.getResource(
      'https://atomicdata.dev/properties/createdAt',
    );

    if (resource.error) {
      throw resource.error;
    }

    const atomString = resource.get(core.properties.shortname)!.toString();
    expect(atomString).toBe('created-at');
  });

  it('a 404 for a custom default property does not clobber an already-cached healthy resource with an error', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    // A user-defined default property (e.g. from lib/defaults/forms.json),
    // populated locally via --repopulate-defaults but never published to the
    // real atomicdata.dev — mirrors https://atomicdata.dev/properties/form-fields.
    const propertySubject = 'https://atomicdata.dev/properties/form-fields';

    // Simulate the property already being known-good in the store, e.g.
    // hydrated once from OPFS/local defaults.
    const goodProperty = new Resource(propertySubject);
    await goodProperty.set(core.properties.shortname, 'form-fields', false);
    await goodProperty.set(
      core.properties.description,
      'The fields of a FormPage.',
      false,
    );
    await goodProperty.set(
      core.properties.datatype,
      Datatype.RESOURCEARRAY,
      false,
    );
    await goodProperty.set(core.properties.isA, [core.classes.property], false);
    store.addResource(goodProperty);

    expect(store.resources.get(propertySubject)?.error).toBeUndefined();

    // Simulate the live network fetch that `resource.set()`'s datatype
    // validation (`getProperty` -> `getResource`) used to issue whenever this
    // subject wasn't already resolved in-memory this session (common during
    // form-builder field creation/edits). Because this subject only exists
    // on the LOCAL dev server, the real atomicdata.dev 404s on it.
    store.injectFetch(async () => new Response('Not found', { status: 404 }));

    await store.fetchResourceFromServer(propertySubject, {
      noWebSocket: true,
    });

    const after = store.resources.get(propertySubject);

    // The propvals survive the failed fetch...
    expect(after?.get(core.properties.shortname)).toBe('form-fields');
    // ...and the resource must NOT be marked errored — it already had valid,
    // complete local data, and a content-free 404 shouldn't override that
    // (`Resource.merge`'s content-free-failure guard).
    expect(after?.error).toBeUndefined();
  });

  it('editing a resource (resource.set validation) does NOT refetch a property that is already cached and healthy', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    const propertySubject = 'https://atomicdata.dev/properties/form-fields';

    const goodProperty = new Resource(propertySubject);
    await goodProperty.set(core.properties.shortname, 'form-fields', false);
    await goodProperty.set(
      core.properties.datatype,
      Datatype.RESOURCEARRAY,
      false,
    );
    await goodProperty.set(core.properties.isA, [core.classes.property], false);
    store.addResource(goodProperty);

    const fetchSpy = vi.fn(async () => new Response('Not found', { status: 404 }));
    store.injectFetch(fetchSpy);

    // Mirrors `useFormFieldPropertySync`'s `page.set(forms.properties.formFields, [...])`
    const page = new Resource('https://example.com/some-form-page');
    store.addResource(page);
    await page.set(propertySubject, ['https://example.com/field-1']);

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(store.resources.get(propertySubject)?.error).toBeUndefined();
  });

  it('getResource() checks the local WASM DB (OPFS) before hitting the network', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    // Not yet touched this session — nothing in `store.resources` yet.
    const propertySubject = 'https://atomicdata.dev/properties/form-fields';
    const jsonAd = JSON.stringify({
      '@id': propertySubject,
      [core.properties.shortname]: 'form-fields',
      [core.properties.datatype]: Datatype.RESOURCEARRAY,
      [core.properties.isA]: [core.classes.property],
    });

    // OPFS already has it (e.g. seeded from lib/defaults/forms.json via
    // --repopulate-defaults), even though the in-memory store doesn't yet.
    store.setClientDb({
      isReady: true,
      waitForReady: async () => true,
      getResource: async (s: string) => (s === propertySubject ? jsonAd : null),
    } as unknown as Parameters<Store['setClientDb']>[0]);

    const fetchSpy = vi.fn(async () => new Response('Not found', { status: 404 }));
    store.injectFetch(fetchSpy);

    const resource = await store.getResource(propertySubject);

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(resource.error).toBeUndefined();
    expect(resource.get(core.properties.shortname)).toBe('form-fields');
  });

  it('getResourceLoading() on a subject that genuinely does not exist still settles into an error, not stuck loading forever', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    store.setServerConnected(true);
    // No clientDb at all — nothing local, matching a subject that has never
    // existed anywhere (not a case the content-free-failure merge guard
    // should protect, since there's no "already had something better" here).
    store.injectFetch(async () => new Response('Not found', { status: 404 }));

    const subject = 'https://example.com/does-not-exist';
    const resource = store.getResourceLoading(subject);

    expect(resource.loading).toBe(true);

    for (let i = 0; i < 50 && resource.loading; i++) {
      await new Promise(res => setTimeout(res, 10));
    }

    expect(resource.loading).toBe(false);
    expect(resource.error).toBeDefined();
  });

  it('accepts a custom fetch implementation', async ({ expect }) => {
    const testResourceSubject = 'https://atomicdata.dev';

    const customFetch = vi.fn(
      async (url: RequestInfo | URL, options: RequestInit | undefined) => {
        return fetch(url, options);
      },
    );

    const store = new Store();

    await store.fetchResourceFromServer(testResourceSubject, {
      noWebSocket: true,
    });

    expect(customFetch.mock.calls).toHaveLength(0);

    store.injectFetch(customFetch);

    await store.fetchResourceFromServer(testResourceSubject, {
      noWebSocket: true,
    });

    expect(customFetch.mock.calls).toHaveLength(1);
  });

  it('creates new resources using store.newResource()', async ({ expect }) => {
    const store = new Store({ serverUrl: 'https://myserver.dev' });
    // Seed core vocab so property validation resolves from cache instead of
    // fetching atomicdata.dev (keeps the test hermetic + fast).
    await bootstrapCoreVocab(store);

    const resource1 = await store.newResource<Core.Property>({
      subject: 'https://myserver.dev/testthing',
      parent: 'https://myserver.dev/properties',
      isA: core.classes.property,
      propVals: {
        [core.properties.datatype]: Datatype.SLUG,
        [core.properties.shortname]: 'testthing',
      },
    });

    expect(resource1.props.parent).toBe('https://myserver.dev/properties');
    expect(resource1.props.datatype).toBe(Datatype.SLUG);
    expect(resource1.props.shortname).toBe('testthing');
    expect(resource1.hasClasses(core.classes.property)).toBe(true);

    const resource2 = await store.newResource({ did: false });

    expect(resource2.props.parent).toBe('https://myserver.dev/');
    expect(resource2.get(core.properties.isA)).toBe(undefined);
  });

  it('normalizes the default root parent when creating resources', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://myserver.dev' });

    const resource = await store.newResource({ did: false });

    expect(resource.props.parent).toBe('https://myserver.dev/');
  });

  it('resolves aliases correctly', async ({ expect }) => {
    const store = new Store();
    const alias = 'https://atomicdata.dev/alias';
    const did = 'did:ad:123';

    const resource = new Resource(did);
    await resource.set(core.properties.description, 'Identity verified', false);

    // Explicitly add with alias
    store.addResource(resource, { alias });

    // Both subjects should return the same resource
    const gotByAlias = store.getResourceLoading(alias);
    const gotByDID = store.getResourceLoading(did);

    expect(gotByAlias.subject).toBe(did);
    expect(gotByDID.subject).toBe(did);
    expect(gotByAlias).toBe(gotByDID);
  });

  it('normalizes relative subjects to full URLs', async ({ expect }) => {
    const store = new Store({ serverUrl: 'https://myserver.dev' });

    // Relative path should become full URL
    const normalizedRelative = store.normalizeSubject('classes');
    expect(normalizedRelative).toBe('https://myserver.dev/classes');

    // Full URL should remain unchanged
    const normalizedFull = store.normalizeSubject(
      'https://myserver.dev/classes?page_size=10',
    );
    expect(normalizedFull).toBe('https://myserver.dev/classes?page_size=10');

    // DID should remain unchanged
    const normalizedDID = store.normalizeSubject('did:ad:123');
    expect(normalizedDID).toBe('did:ad:123');
  });

  it('uses ClientDb.search for offline local hits', async ({ expect }) => {
    const store = new Store({ serverUrl: 'https://atomicdata.dev' });
    const driveSubject = 'https://atomicdata.dev/test-drive';
    const subject = 'https://atomicdata.dev/offline-search-target';
    const name = 'ZephyrQuokkaOfflineTarget';
    let searched: { query: string; parents?: string | string[] } | undefined;
    const fakeClientDb = {
      isReady: true,
      isInitialized: true,
      initError: undefined,
      waitForReady: async () => true,
      search: async (
        query: string,
        opts: { parents?: string | string[] } = {},
      ) => {
        searched = { query, parents: opts.parents };

        return query === name ? [subject] : [];
      },
    };

    store.setClientDb(
      fakeClientDb as unknown as Parameters<Store['setClientDb']>[0],
    );

    const results = await store.search(name, { parents: driveSubject });

    expect(searched).toEqual({ query: name, parents: driveSubject });
    expect(results).toEqual([subject]);
  });

  it('excludes subjects with a pending outbox entry from the VV sync state (F1 interim)', async ({
    expect,
  }) => {
    // planning/unified-sync.md F1: a subject mid-backoff (or just not yet
    // drained this pass) must not appear in the VV state sent to the
    // server — otherwise the server sees the client "ahead" and requests
    // a SYNC_PUSH of the raw, unsigned Loro bytes for it, bypassing the
    // outbox's signed-commit path (and the hub's rights check) entirely.
    const { store } = await testStore();
    const driveSubject = 'https://example.com/drive';

    const clean = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Folder',
      propVals: { [core.properties.name]: 'Clean' },
      parent: driveSubject,
    });
    await clean.save();

    const dirty = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Folder',
      propVals: { [core.properties.name]: 'Dirty' },
      parent: driveSubject,
    });
    await dirty.save();

    // Simulate a pending outbox entry that hasn't drained yet — e.g. mid
    // backoff after a prior failed attempt.
    store.outbox.markDirty(dirty.subject);

    const syncState = await store.computeDriveSyncState(driveSubject);

    expect(syncState.resources[clean.subject]).toBeDefined();
    expect(syncState.resources[dirty.subject]).toBeUndefined();
  });

  it('cold-drains outbox entries for subjects no longer in memory', async ({
    expect,
  }) => {
    // Reload-stranded entry (planning/completed/outbox-drain-data-loss-race.md, root
    // cause 3): an outbox entry restored from localStorage after a page load,
    // for a subject nothing on the current page renders. The drain must load
    // the resource itself and POST the pending delta — returning silently
    // would leave `pendingDirtyCount` stuck > 0 forever and never deliver
    // the write.
    const { store, posted } = await testStore();

    const resource = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Folder',
      propVals: { [core.properties.name]: 'Before' },
      parent: 'https://example.com/drive',
    });
    await resource.save();
    const subject = resource.subject;
    const postedBefore = posted.length;

    // Edit, then simulate the reload: the dirty bit is in the outbox (as if
    // hydrated from localStorage) but the resource is gone from memory.
    await resource.set(core.properties.name, 'After', false);
    store.outbox.markDirty(subject);
    store.resources.delete(subject);

    // The cold drain "loads" it — stub the fetch to hand the hydrated
    // resource back, like the OPFS/server path would.
    const getResourceSpy = vi
      .spyOn(store, 'getResource')
      .mockImplementation(async (s: string) => {
        expect(s).toBe(subject);
        store.resources.set(subject, resource);

        return resource;
      });

    await store.syncDirtyResources();

    expect(getResourceSpy).toHaveBeenCalled();
    expect(posted.length).toBe(postedBefore + 1);
    expect(store.outbox.hasPending(subject)).toBe(false);
    expect(store.getSyncStatus().pendingDirtyCount).toBe(0);
  });

  it('counts scheduled (debounce-pending) saves in sync status', ({
    expect,
  }) => {
    // UI layers (useValue's commitDebounce) park a save() in a timer; until
    // it fires the edit is only in memory. Sync status must not report
    // "fully synced" during that window (planning/completed/outbox-drain-data-loss-race.md).
    const store = new Store({ serverUrl: 'https://example.com' });

    expect(store.getSyncStatus().pendingDirtyCount).toBe(0);
    expect(store.getSyncStatus().syncInProgress).toBe(false);

    store.startScheduledSave();
    store.startScheduledSave();
    expect(store.getSyncStatus().pendingDirtyCount).toBe(2);
    expect(store.getSyncStatus().syncInProgress).toBe(true);

    store.finishScheduledSave();
    expect(store.getSyncStatus().pendingDirtyCount).toBe(1);

    store.finishScheduledSave();
    expect(store.getSyncStatus().pendingDirtyCount).toBe(0);
    expect(store.getSyncStatus().syncInProgress).toBe(false);

    // Unbalanced finish must not go negative and mask real dirty state.
    store.finishScheduledSave();
    expect(store.getSyncStatus().pendingDirtyCount).toBe(0);
  });
});
