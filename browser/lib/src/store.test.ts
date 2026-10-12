import { enableLoro } from './loro-loader.js';
import { describe, it, vi, afterEach } from 'vitest';
import { Resource, Store, core, Core, Datatype } from './index.js';
import { bootstrapCoreVocab } from './test-vocab.js';
import { testStore } from './test-store.js';

describe('Store', () => {
  it('settles concurrent readers when a WebSocket GET fails', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    const subject = 'https://example.com/app';
    const placeholder = new Resource(subject);
    placeholder.loading = true;
    store.addResource(placeholder);
    const failure = new Error('Resource not found.');
    vi.spyOn(store, 'getWebSocketForSubject').mockReturnValue({
      readyState: WebSocket.OPEN,
      fetch: vi.fn().mockRejectedValue(failure),
      unsubscribeAgentProfile: vi.fn(),
      subscribeAgentProfile: vi.fn(),
    } as never);
    const waiting = store.getResource(subject);
    const fetched = await store.fetchResourceFromServer(subject);
    expect(fetched.error).toBe(failure);
    expect(fetched.loading).toBe(false);
    expect((await waiting).error).toBe(failure);
    expect((await store.getResource(subject)).error).toBe(failure);
  });

  it('does not start a second fetch when applying a received snapshot', async ({
    expect,
  }) => {
    await enableLoro();
    const store = new Store({ serverUrl: 'https://example.com' });
    store.setServerConnected(true);
    const source = new Resource('https://example.com/query?property=parent');
    await source.set(
      core.properties.isA,
      ['https://atomicdata.dev/classes/Folder'],
      false,
    );
    await source.set(core.properties.name, 'Received snapshot', false);
    const fetch = vi
      .spyOn(store, 'fetchResourceFromServer')
      .mockResolvedValue(source as never);
    store.applyIncoming({
      subject: source.subject,
      loroBytes: source.getLoroDoc()!.export({ mode: 'snapshot' }),
      source: 'http-fetch',
      replaceLoroDocsFromRemote: true,
    });
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(fetch).not.toHaveBeenCalled();
    expect(
      store.getResourceLoading(source.subject).get(core.properties.name),
    ).toBe('Received snapshot');
  });

  it('tracks immutable save status across cancellation and offline queueing', async ({
    expect,
  }) => {
    vi.useFakeTimers();

    try {
      const store = new Store();
      const resource = new Resource('_new:save-state');
      resource.setStore(store);
      const idle = store.getSaveState(resource);
      const changed = vi.fn();
      const unsubscribe = store.subscribeSaveState(resource, changed);
      const scheduler = store.createSaveScheduler(resource);
      scheduler.schedule(100);
      const queuedTimer = store.getSaveState(resource);
      expect(queuedTimer.kind).toBe('scheduled');
      expect(store.getSaveState(resource)).toBe(queuedTimer);
      expect(idle.kind).toBe('idle');
      expect(Object.isFrozen(queuedTimer)).toBe(true);
      // A temporary row keeps the same owner after acquiring its DID.
      resource.setSubject('did:ad:saved-row');
      expect(store.getSaveState(resource).scheduledCount).toBe(1);
      scheduler.cancel();
      expect(store.getSyncStatus().pendingDirtyCount).toBe(0);
      store.outbox.markDirty(resource.subject);
      expect(store.getSaveState(resource)).toMatchObject({
        kind: 'queued',
        reason: 'offline',
      });
      expect(changed).toHaveBeenCalled();
      unsubscribe();
      changed.mockClear();
      scheduler.schedule(100);
      scheduler.cancel();
      expect(changed).not.toHaveBeenCalled();
      store.outbox.clearDirty(resource.subject);
    } finally {
      vi.useRealTimers();
    }
  });

  it('publishes direct save start and finish without changing read readiness', async ({
    expect,
  }) => {
    const { store } = await testStore();
    const resource = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Folder',
      propVals: { [core.properties.name]: 'Save status' },
      parent: 'https://example.com/drive',
    });
    const states: string[] = [];
    const unsubscribe = store.subscribeSaveState(resource, () =>
      states.push(store.getSaveState(resource).kind),
    );
    await resource.save();
    expect(states).toContain('saving');
    expect(store.getSaveState(resource).kind).toBe('idle');
    expect(resource.isReady()).toBe(true);
    unsubscribe();
  });

  it('captures immutable read status while retaining the stable mutation handle', ({
    expect,
  }) => {
    const store = new Store();
    const resource = new Resource('did:ad:status-snapshot');
    resource.loading = true;
    store.addResource(resource);
    const before = store.getResourceSnapshot(resource.subject);
    expect(before.ready).toBe(false);
    expect(before.readState).toBe('loading');
    expect(store.getResourceSnapshot(resource.subject)).toBe(before);
    resource.loading = false;
    store.notifyResourceUpdated(resource);
    const after = store.getResourceSnapshot(resource.subject);
    expect(after).not.toBe(before);
    expect(after.ready).toBe(true);
    expect(before.ready).toBe(false);
    expect(after.resource).toBe(before.resource);
    expect(Object.isFrozen(after)).toBe(true);
  });

  it('publishes local hydration only after restoring the causal snapshot', async ({
    expect,
  }) => {
    await enableLoro();
    const subject = 'did:ad:atomic-hydration';
    const source = new Resource(subject);
    await source.set(core.properties.name, 'Persisted', false);
    const doc = source.getLoroDoc()!;
    const snapshot = doc.export({ mode: 'snapshot' });
    const version = doc.oplogVersion().toJSON();
    const store = new Store({ serverUrl: 'https://example.com' });
    store.setClientDb({
      isReady: true,
      isInitialized: true,
      waitForInit: async () => {},
      getResourceWithSnapshot: async () => ({
        jsonAd: JSON.stringify({
          '@id': subject,
          [core.properties.name]: 'Persisted',
        }),
        snapshot,
      }),
    } as unknown as Parameters<Store['setClientDb']>[0]);
    const published: unknown[] = [];
    const apply = store.applyIncoming.bind(store);
    vi.spyOn(store, 'applyIncoming').mockImplementation(change => {
      if (change.source === 'offline-replay') {
        published.push(change.resource?.getLoroDoc()?.oplogVersion().toJSON());
      }

      return apply(change);
    });
    store.getResourceLoading(subject);
    await vi.waitFor(() => expect(published).toHaveLength(1));
    expect(published).toEqual([version]);
  });

  it('keeps property readers waiting while a delta with missing history is recovered', async ({
    expect,
  }) => {
    await enableLoro();
    const store = new Store({ serverUrl: 'https://example.com' });
    const source = new Resource('did:ad:partial-property');
    await source.set(core.properties.isA, [core.classes.property], false);
    const doc = source.getLoroDoc()!;
    doc.commit();
    const base = doc.oplogVersion();
    await source.set(core.properties.datatype, Datatype.STRING, false);
    await source.set(core.properties.shortname, 'title', false);
    await source.set(core.properties.description, 'Title', false);
    doc.commit();
    const placeholder = new Resource(source.subject);
    placeholder.loading = true;
    store.addResource(placeholder);
    let recover!: () => void;
    vi.spyOn(store, 'fetchResourceFromServer').mockImplementation(async () => {
      await new Promise<void>(resolve => {
        recover = resolve;
      });
      store.applyIncoming({
        subject: source.subject,
        resource: source,
        source: 'http-fetch',
      });

      return source;
    });
    const settled = vi.fn();
    const result = store.getProperty(source.subject).then(
      value => {
        settled();

        return value;
      },
      error => {
        settled();

        return error;
      },
    );
    store.applyIncoming({
      subject: source.subject,
      loroBytes: doc.export({ mode: 'update', from: base }),
      source: 'ws-sub-push',
    });
    await new Promise(resolve => setTimeout(resolve, 0));
    const early = settled.mock.calls.length;
    recover();
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(await result).toMatchObject({ datatype: Datatype.STRING });
    expect(early).toBe(0);
  });

  it('materializes a buffered property snapshot before returning its datatype', async ({
    expect,
  }) => {
    await enableLoro();
    const store = new Store();
    const source = new Resource('did:ad:buffered-property');
    await source.set(core.properties.datatype, Datatype.STRING, false);
    await source.set(core.properties.shortname, 'title', false);
    await source.set(core.properties.description, 'Title', false);
    const snapshot = source.getLoroDoc()!.export({ mode: 'snapshot' });
    const loaded = new Resource(source.subject);
    loaded.applyHydratedValues([
      ['https://atomicdata.dev/properties/loroUpdate', snapshot],
    ]);
    store.addResource(loaded);
    expect(await store.getProperty(source.subject)).toMatchObject({
      datatype: Datatype.STRING,
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('waits for a loading resource to settle before resolving an async read', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    const resource = new Resource('did:ad:loading-property');
    resource.loading = true;
    store.addResource(resource);
    const resolved = vi.fn();
    const pending = store.getResource(resource.subject).then(resolved);
    store.notifyResourceUpdated(resource);
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(resolved).not.toHaveBeenCalled();
    resource.loading = false;
    store.notifyResourceUpdated(resource);
    await pending;
    expect(resolved).toHaveBeenCalledWith(resource);
  });

  it('preserves persisted Loro history when getResource loads a profile offline', async ({
    expect,
  }) => {
    await enableLoro();
    const subject = 'did:ad:agent:offline-profile';
    const serverProfile = new Resource(subject);
    const doc = serverProfile.getLoroDoc()!;

    for (let i = 0; i < 20; i++) {
      await serverProfile.set(core.properties.name, `Name ${i}`, false);
      doc.commit();
    }

    const snapshot = doc.export({ mode: 'snapshot' });
    const jsonAd = JSON.stringify({
      '@id': subject,
      [core.properties.name]: 'Name 19',
    });
    const store = new Store({ serverUrl: 'https://example.com' });
    store.setClientDb({
      isReady: true,
      isInitialized: true,
      waitForInit: async () => {},
      getResource: async () => jsonAd,
      getResourceWithSnapshot: async () => ({ jsonAd, snapshot }),
    } as unknown as Parameters<Store['setClientDb']>[0]);
    const profile = await store.getResource(subject);
    await profile.set(core.properties.name, 'Renamed', false);
    doc.import(profile.getLoroDoc()!.export({ mode: 'snapshot' }));
    expect(doc.getMap('properties').get(core.properties.name)).toBe('Renamed');
  });

  it('keeps a local-only drive ready when a reader requests a server refresh', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    const drive = new Resource('did:ad:local-drive');
    await drive.set(core.properties.name, 'Local drive', false);
    drive.loading = false;
    store.addResource(drive);
    store.registerLocalOnlyDrive(drive.subject);
    const fetch = vi.fn(async () => new Response('not found', { status: 404 }));
    store.injectFetch(fetch);
    const result = await store.fetchResourceFromServer(drive.subject, {
      setLoading: true,
    });
    expect(fetch).not.toHaveBeenCalled();
    expect(result.isReady()).toBe(true);
    expect(result.get(core.properties.name)).toBe('Local drive');
  });

  it('waits for property data after a loading-placeholder notification', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    const resource = new Resource('did:ad:loading-property');
    resource.loading = true;
    store.addResource(resource);
    const settled = vi.fn();
    const result = store.getProperty(resource.subject).then(
      value => {
        settled();

        return value;
      },
      error => {
        settled();

        return error;
      },
    );
    // Mounted readers can notify subscribers before hydration finishes.
    store.notifyResourceUpdated(resource);
    await new Promise(resolve => setTimeout(resolve, 0));
    const settledWhileLoading = settled.mock.calls.length;
    await resource.set(core.properties.datatype, Datatype.STRING, false);
    await resource.set(core.properties.shortname, 'title', false);
    await resource.set(core.properties.description, 'Title', false);
    resource.loading = false;
    store.notifyResourceUpdated(resource);
    const loaded = await result;
    expect(settledWhileLoading).toBe(0);
    expect(loaded).toMatchObject({
      shortname: 'title',
      datatype: Datatype.STRING,
    });
  });

  it('reports a failed property load without waiting for the loading flag to clear', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    const resource = new Resource('did:ad:failed-property');
    resource.loading = true;
    store.addResource(resource);
    const result = store.getProperty(resource.subject);
    const rejected = expect(result).rejects.toThrow(
      'cannot be loaded: Error: unavailable',
    );
    resource.error = new Error('unavailable');
    store.notifyResourceUpdated(resource);
    await rejected;
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

  it('attaches a file to an unsaved form under the subject the form is saved as', async ({
    expect,
  }) => {
    const { store, posted } = await testStore();
    const drive = await store.createDrive('Home');
    store.setDrive(drive.subject);
    // The new-resource form's draft: its subject is final from creation, and
    // its genesis is signed on save.
    const parent = await store.newResource({
      parent: drive.subject,
      isA: 'https://atomicdata.dev/classes/Folder',
      deferGenesis: true,
    });
    const formSubject = parent.subject;
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
    expect(parent.subject).toMatch(/^atomic:/);
    expect(parent.subject).toBe(formSubject);
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

  it('an acknowledged edit waits for its durable snapshot before save resolves', async () => {
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
    const putResourceWithSnapshot = vi.fn(() => pendingWrite);
    const flush = vi.fn(() => Promise.reject(new Error('worker destroyed')));
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
        expect(putResourceWithSnapshot).toHaveBeenCalled(),
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
    expect(flush).not.toHaveBeenCalled();
  });

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
      undefined,
    );
  });

  it('writes the same client-DB row from addResource and persistToClientDb', async ({
    expect,
  }) => {
    await enableLoro();
    const store = new Store({ serverUrl: 'https://example.com' });
    const putResourceWithSnapshot = vi.fn().mockResolvedValue(undefined);
    store.setClientDb({
      isReady: true,
      flush: async () => undefined,
      putResourceWithSnapshot,
    } as unknown as Parameters<Store['setClientDb']>[0]);

    const binaryProp = 'https://example.com/properties/bytes';
    const loroUpdate = 'https://atomicdata.dev/properties/loroUpdate';
    const resource = new Resource('did:ad:same-row-both-paths');
    resource.setStore(store);
    await resource.set(
      core.properties.isA,
      ['https://atomicdata.dev/classes/Folder'],
      false,
    );
    await resource.set(core.properties.name, 'Same row', false);
    // A binary propval and a Loro snapshot are the two entry kinds a row
    // must leave out: the first is a Uint8Array aux value, the second is the
    // doc itself and travels next to the row.
    resource.applyHydratedValues([
      [binaryProp, new Uint8Array([1, 2, 3])],
      [loroUpdate, resource.getLoroDoc()!.export({ mode: 'snapshot' })],
    ]);
    resource.loading = false;
    resource.new = false;
    expect(resource.getEntries().map(([k]) => k)).toContain(binaryProp);

    store.addResource(resource);
    expect(putResourceWithSnapshot).toHaveBeenCalledTimes(1);
    await resource.persistToClientDb();
    expect(putResourceWithSnapshot).toHaveBeenCalledTimes(2);

    const [, rowFromAddResource, snapshotFromAddResource] =
      putResourceWithSnapshot.mock.calls[0];
    const [, rowFromPersist, snapshotFromPersist] =
      putResourceWithSnapshot.mock.calls[1];
    expect(rowFromPersist).toBe(rowFromAddResource);
    expect(rowFromPersist).toBe(resource.toClientDbJsonAd());
    expect(snapshotFromAddResource).toBeInstanceOf(Uint8Array);
    expect(snapshotFromPersist).toBeInstanceOf(Uint8Array);

    const row = JSON.parse(rowFromPersist);
    expect(row['@id']).toBe(resource.subject);
    expect(row[core.properties.name]).toBe('Same row');
    expect(row[core.properties.isA]).toEqual([
      'https://atomicdata.dev/classes/Folder',
    ]);
    expect(row).not.toHaveProperty(binaryProp);
    expect(row).not.toHaveProperty(loroUpdate);
  });

  it('does not rewrite a row that persistToClientDb already wrote', async ({
    expect,
  }) => {
    await enableLoro();

    const build = async () => {
      const store = new Store({ serverUrl: 'https://example.com' });
      const putResourceWithSnapshot = vi.fn().mockResolvedValue(undefined);
      store.setClientDb({
        isReady: true,
        flush: async () => undefined,
        putResourceWithSnapshot,
      } as unknown as Parameters<Store['setClientDb']>[0]);
      // Canonical spelling: `persistToClientDb` keys the row by the
      // resource's own subject, which `addResource` would otherwise rewrite.
      const resource = new Resource('atomic:persisted-then-added');
      resource.setStore(store);
      await resource.set(core.properties.name, 'Persisted first', false);
      resource.loading = false;
      resource.new = false;

      return { store, resource, putResourceWithSnapshot };
    };

    // Control: the ingress path writes a resource the store has not seen.
    const control = await build();
    control.store.addResource(control.resource);
    expect(control.putResourceWithSnapshot).toHaveBeenCalledTimes(1);

    // The durable save path wrote the row; the ingress that follows (a WS
    // echo, a notify) finds the same state on disk and skips its write.
    const { store, resource, putResourceWithSnapshot } = await build();
    await resource.persistToClientDb();
    expect(putResourceWithSnapshot).toHaveBeenCalledTimes(1);
    store.addResource(resource);
    expect(putResourceWithSnapshot).toHaveBeenCalledTimes(1);
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

    const fetchSpy = vi.fn(
      async () => new Response('Not found', { status: 404 }),
    );
    store.injectFetch(fetchSpy);

    // Mirrors `useFormFieldPropertySync`'s `page.set(forms.properties.formFields, [...])`
    const page = new Resource('https://example.com/some-form-page');
    store.addResource(page);
    await page.set(propertySubject, ['https://example.com/field-1']);

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(store.resources.get(propertySubject)?.error).toBeUndefined();
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

    // Both requests are answered locally: the test is about which fetch the
    // store uses, and waiting on the real atomicdata.dev made it flaky in CI.
    const answer = async () =>
      new Response(JSON.stringify({ '@id': testResourceSubject }), {
        headers: { 'Content-Type': 'application/ad+json' },
      });
    const globalFetch = vi.fn(answer);
    vi.stubGlobal('fetch', globalFetch);
    const customFetch = vi.fn(
      async (_url: RequestInfo | URL, _options: RequestInit | undefined) =>
        answer(),
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
    vi.unstubAllGlobals();
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

  it('returns the canonical resource when an HTTP query responds with an alias', async ({
    expect,
  }) => {
    const store = new Store();
    const canonical = new Resource('https://atomicdata.dev/query?canonical=1');
    await canonical.set(core.properties.name, 'Query result', false);
    vi.spyOn(store.client, 'fetchResourceHTTP').mockResolvedValue({
      resource: canonical,
      createdResources: [],
    });
    const result = await store.fetchResourceFromServer(
      'https://atomicdata.dev/query?requested=1',
      { noWebSocket: true },
    );
    expect(result).toBe(canonical);
    expect(result.title).toBe('Query result');
  });

  it('resolves aliases correctly', async ({ expect }) => {
    const store = new Store();
    const alias = 'https://atomicdata.dev/alias';
    // Legacy `did:ad:` in; the store canonicalizes the subject to `atomic:`.
    const did = 'did:ad:123';
    const canonicalDid = 'atomic:123';

    const resource = new Resource(did);
    await resource.set(core.properties.description, 'Identity verified', false);

    // Explicitly add with alias
    store.addResource(resource, { alias });

    // Both subjects should return the same resource
    const gotByAlias = store.getResourceLoading(alias);
    const gotByDID = store.getResourceLoading(did);

    expect(gotByAlias.subject).toBe(canonicalDid);
    expect(gotByDID.subject).toBe(canonicalDid);
    expect(gotByAlias).toBe(gotByDID);
  });

  it('returns a DID resource fetched by its HTTP path alias', async ({
    expect,
  }) => {
    // The server still answers with the legacy `did:ad:` spelling; the
    // store canonicalizes the fetched resource to `atomic:`.
    const did = 'did:ad:ontology123';
    const canonicalDid = 'atomic:ontology123';
    const httpAlias = `https://example.com/${did}`;
    const store = new Store({ serverUrl: 'https://example.com' });
    store.setServerConnected(true);
    store.injectFetch(
      async () =>
        new Response(
          JSON.stringify({
            '@id': did,
            [core.properties.name]: 'My ontology',
          }),
          { status: 200 },
        ),
    );

    const resource = await store.fetchResourceFromServer(httpAlias, {
      noWebSocket: true,
    });

    expect(resource).toBeDefined();
    expect(resource.error).toBeUndefined();
    expect(resource.subject).toBe(canonicalDid);
    expect(resource.get(core.properties.name)).toBe('My ontology');
    expect(store.getResourceLoading(httpAlias).subject).toBe(canonicalDid);
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

    // Canonical Atomic identifiers remain unchanged
    expect(store.normalizeSubject('atomic:123')).toBe('atomic:123');

    // Legacy `did:ad:` is canonicalized to `atomic:`
    const normalizedDID = store.normalizeSubject('did:ad:123');
    expect(normalizedDID).toBe('atomic:123');
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

  it('drops destroyed subjects from local search answers', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://atomicdata.dev' });
    const alive = 'https://atomicdata.dev/search-alive';
    const gone = 'https://atomicdata.dev/search-gone';
    const fakeClientDb = {
      isReady: true,
      isInitialized: true,
      initError: undefined,
      waitForReady: async () => true,
      search: async () => [gone, alive],
      removeResource: async () => undefined,
    };

    store.setClientDb(
      fakeClientDb as unknown as Parameters<Store['setClientDb']>[0],
    );
    store.removeResource(gone);

    const results = await store.search('anything', {
      parents: 'https://atomicdata.dev/test-drive',
    });

    expect(results).toEqual([alive]);
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

  it('builds a sparse sync state whose size does not grow with the peer count', async ({
    expect,
  }) => {
    const { store } = await testStore();
    const driveSubject = 'https://example.com/drive';
    const children = [];

    // Every resource created on a client has a peer of its own.
    for (let i = 0; i < 12; i++) {
      const child = await store.newResource({
        isA: 'https://atomicdata.dev/classes/Folder',
        propVals: { [core.properties.name]: `Child ${i}` },
        parent: driveSubject,
      });
      await child.save();
      children.push(child);
    }

    const dense = await store.computeDriveSyncState(driveSubject);
    const sparse = await store.computeDriveSyncState(driveSubject, {
      sparse: true,
    });

    expect(sparse.hashVersion).toBe(2);
    expect(sparse.resources).toEqual({});
    expect(Object.keys(sparse.vvs!).sort()).toEqual(
      Object.keys(dense.resources).sort(),
    );

    // Same information as the dense matrix, without the zeros.
    for (const [subject, counters] of Object.entries(dense.resources)) {
      const expected = Object.fromEntries(
        counters
          .map((counter, i) => [dense.peers[i], counter] as const)
          .filter(([, counter]) => counter !== 0),
      );
      expect(sparse.vvs![subject]).toEqual(expected);
    }

    // Dense is resources x peers, sparse is the non-zero entries only.
    const denseCells = Object.values(dense.resources).reduce(
      (sum, counters) => sum + counters.length,
      0,
    );
    const sparseCells = Object.values(sparse.vvs!).reduce(
      (sum, vv) => sum + Object.keys(vv).length,
      0,
    );
    expect(dense.peers.length).toBeGreaterThanOrEqual(children.length);
    expect(sparseCells).toBeLessThan(denseCells / 4);
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

  it('recovers from a server pending-deps rejection by re-sending a full snapshot', async ({
    expect,
  }) => {
    // Incident class: the save cursor sits PAST ops the server never
    // received (an earlier commit was lost in transit after the cursor
    // advanced), so every exported delta depends on ops the server doesn't
    // have. The server now rejects those ("parked as pending"); the drain
    // must react by dropping the cursor so the next attempt exports a
    // self-contained snapshot that re-delivers the lost range.
    const { store, posted, postCommitSpy } = await testStore();
    const name = core.properties.name;
    const description = core.properties.description;

    const resource = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Folder',
      propVals: { [name]: 'Before' },
      parent: 'https://example.com/drive',
    });
    await resource.save();
    const subject = resource.subject;

    // The "lost" edit: committed locally, then the cursor is (wrongly)
    // advanced past it without the server ever seeing a commit — the state
    // the incident left the client in.
    await resource.set(description, 'the lost edit', false);
    resource.getLoroDoc()!.commit();
    resource.markLoroSavedAt(resource.getLoroDoc()!.oplogVersion());

    // Next edit exports a delta starting past the lost ops; the server
    // rejects it the way lib/src/commit.rs now does.
    postCommitSpy.mockImplementationOnce(async () => {
      throw new Error(
        "Commit's Loro update depends on ops the server does not have — the " +
          'update was parked as pending and none of its changes could be applied.',
      );
    });
    await resource.set(name, 'After', false);
    const postedBefore = posted.length;
    // `save()` reports the refusal (#1460) …
    await expect(resource.save()).rejects.toThrow('parked as pending');

    // … but the rejected attempt must keep the entry queued (not drop it) …
    expect(store.outbox.hasPending(subject)).toBe(true);

    // … and the retry (once due) must send a FULL snapshot. Clear the
    // backoff window so the next drain attempts immediately.
    const entry = store.outbox.getEntry(subject)!;
    entry.failures = 0;
    entry.lastAttemptAt = undefined;
    await store.syncDirtyResources();

    expect(posted.length).toBe(postedBefore + 1);
    const resent = posted[posted.length - 1];

    // Self-contained proof: the resent bytes import COMPLETE into a fresh
    // doc (a delta would leave pending ops) and carry BOTH edits — the
    // lost one and the new one.
    const probe = new Resource(subject);
    const { complete } = probe.importLoroUpdate(resent.loroUpdate!);
    expect(complete).toBe(true);
    expect(probe.get(name)).toBe('After');
    expect(probe.get(description)).toBe('the lost edit');
    expect(store.outbox.hasPending(subject)).toBe(false);
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
