import { describe, it, vi } from 'vitest';
import { Commit, isCommitSubject } from './commit.js';
import { Store } from './store.js';
import { Resource } from './resource.js';
import { core } from './index.js';
import { testStore } from './test-store.js';
import { isAtomicIdentifier } from './subject.js';

// Low-level signing primitives (CommitBuilder, _new: subjects, Ed25519
// serialization) live in `sign.test.ts`. This file is the consumer-API
// canary: every test below goes through `store.newResource()` → `set()`
// → `save()` and never touches `CommitBuilder` / `markNextCommitAsGenesis`
// / `syncDirtyResources`.

describe('isCommitSubject', () => {
  it('recognizes both the DID and the legacy URL form', ({ expect }) => {
    expect(isCommitSubject('did:ad:commit:abc123')).toBe(true);
    expect(isCommitSubject('atomic:commit:abc123')).toBe(true);
    expect(
      isCommitSubject('https://staging.atomicdata.dev/commits//Ybe1N6Cu+xy=='),
    ).toBe(true);
  });

  it('leaves ordinary resources alone', ({ expect }) => {
    expect(isCommitSubject('did:ad:resource:abc123')).toBe(false);
    expect(isCommitSubject('https://example.com/01jd9n5hc9dpwm8ygf2v')).toBe(
      false,
    );
    // A folder the user named "commits" is not the reserved route.
    expect(isCommitSubject('https://example.com/my/commits/child')).toBe(false);
    expect(isCommitSubject('_new:something')).toBe(false);
    expect(isCommitSubject('not a url at all')).toBe(false);
  });
});

/**
 * The application-facing flow: create a resource, edit it, save it.
 * No `CommitBuilder`, no `markNextCommitAsGenesis`, no placeholder
 * subjects, no `syncDirtyResources` — `save()` resolves once the
 * server has acked.
 */
describe('Resource save flow', () => {
  it('signs one genesis when two saves race on a draft', async ({ expect }) => {
    const { store, postCommitSpy } = await testStore();
    const drive = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      propVals: { [core.properties.name]: 'Home' },
      noParent: true,
    });
    await drive.save();
    postCommitSpy.mockClear();

    // A table row: a draft under a saved parent whose genesis is signed on
    // its first save, so a second save can slip in before it is.
    const draft = await store.newResource({
      parent: drive.subject,
      deferGenesis: true,
    });
    const subject = draft.subject;
    await draft.set(core.properties.name, 'Raced', false);

    // Editing a draft queues nothing: its writes belong to the genesis.
    expect(store.outbox.hasPending(subject)).toBe(false);

    // A row's materialize timer and its unmount flush can both call save()
    // before either has signed.
    await Promise.all([draft.save(), draft.save()]);

    expect(isAtomicIdentifier(draft.subject)).toBe(true);
    // The id minted at creation is the one that was saved.
    expect(draft.subject).toBe(subject);
    expect(postCommitSpy.mock.calls.length).toBe(1);
    const genesis = postCommitSpy.mock.calls[0][0] as Commit;
    expect(genesis.isGenesis).toBe(true);
    expect(genesis.subject).toBe(subject);
  });

  it('saves a child created under an unsaved draft once the draft is saved', async ({
    expect,
  }) => {
    // A dialog opened from inside a new-resource form creates a child of the
    // form's draft and saves it before the form itself is saved. The draft has
    // its final subject from the start, so the child's `parent` and the batch
    // it waits in are keyed by the subject the draft is saved under.
    const { store, postCommitSpy } = await testStore();
    const drive = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      propVals: { [core.properties.name]: 'Home' },
      noParent: true,
    });
    await drive.save();
    postCommitSpy.mockClear();

    const form = await store.newResource({
      parent: drive.subject,
      deferGenesis: true,
    });
    const child = await store.newResource({
      parent: form.subject,
      deferGenesis: true,
    });
    await child.set(core.properties.name, 'Child', false);

    // The parent does not exist yet, so the child waits for it.
    expect(await child.save()).toBe('queued');
    expect(postCommitSpy).not.toHaveBeenCalled();

    await form.set(core.properties.name, 'Form', false);
    await form.save();
    await store.syncDirtyResources();

    const posted = postCommitSpy.mock.calls.map(c => (c[0] as Commit).subject);
    expect(posted).toEqual([form.subject, child.subject]);
    expect(child.get(core.properties.parent)).toBe(form.subject);
    expect(store.outbox.hasPending(child.subject)).toBe(false);
  });

  it('creates a DID resource and posts sequential saves', async ({
    expect,
  }) => {
    const { store, postCommitSpy } = await testStore();

    const doc = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      propVals: { [core.properties.name]: 'First Save' },
      noParent: true,
    });

    const genesisSubject = doc.subject;
    expect(isAtomicIdentifier(genesisSubject)).toBe(true);
    expect(genesisSubject).not.toBe('did:ad:genesis');
    expect(genesisSubject).not.toBe('atomic:genesis');

    expect(await doc.save()).toBe('persisted');

    // A remote merge that drops `lastCommit` must not break the next
    // save — the resource keeps its own commit cursor.
    doc.removeUnsafe('https://atomicdata.dev/properties/lastCommit');

    await doc.set(
      'https://atomicdata.dev/properties/description',
      'Second',
      false,
    );
    expect(await doc.save()).toBe('persisted');

    // Subject is stable across saves.
    expect(doc.subject).toBe(genesisSubject);

    // Two commits: genesis then an update. No previousCommit chain.
    expect(postCommitSpy.mock.calls.length).toBe(2);
    const first = postCommitSpy.mock.calls[0][0] as Commit;
    const second = postCommitSpy.mock.calls[1][0] as Commit;
    expect(first.isGenesis).toBe(true);
    expect(first.previousCommit).toBeUndefined();
    expect(second.subject).toBe(genesisSubject);
    expect(second.isGenesis).toBeFalsy();
    expect(second.previousCommit).toBeUndefined();
  });

  it('supports typed property setters via the props proxy', async ({
    expect,
  }) => {
    const { store, postCommitSpy } = await testStore();

    const doc = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      propVals: { [core.properties.name]: 'Initial' },
      noParent: true,
    });
    expect(await doc.save()).toBe('persisted');

    // Typed setter: `doc.props.name = …` resolves the shortname to its
    // property URL and writes through `set(…, false)` — the write-side
    // companion of the typed `props` read accessor, so consumers never
    // type `set(core.properties.name, …)`. (Direct `doc.name =` is
    // intentionally NOT offered: flattening props onto the Resource would
    // collide with methods like `save`/`subject`/`parent`.)
    doc.props.name = 'Renamed';
    expect(await doc.save()).toBe('persisted');

    expect(doc.get(core.properties.name)).toBe('Renamed');
    expect(postCommitSpy.mock.calls.length).toBe(2);
  });

  it('a no-op save returns "noop" and posts nothing', async ({ expect }) => {
    const { store, postCommitSpy } = await testStore();

    const doc = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      propVals: { [core.properties.name]: 'Doc' },
      noParent: true,
    });
    await doc.save();
    postCommitSpy.mockClear();

    expect(await doc.save()).toBe('noop');
    expect(postCommitSpy.mock.calls.length).toBe(0);
  });

  it('the genesis commit carries the full initial state', async ({
    expect,
  }) => {
    const { store, postCommitSpy, agentDID } = await testStore();

    const drive = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      noParent: true,
      propVals: {
        [core.properties.name]: 'Test Drive',
        'https://atomicdata.dev/properties/write': [agentDID],
        'https://atomicdata.dev/properties/read': [agentDID],
      },
    });
    expect(await drive.save()).toBe('persisted');

    const genesis = postCommitSpy.mock.calls[0][0] as Commit;
    expect(genesis.loroUpdate).toBeDefined();

    // Materialize the genesis bytes into a fresh resource and check the
    // full state round-trips.
    const materialized = new Resource(genesis.subject);
    materialized.importLoroUpdate(genesis.loroUpdate!);
    expect(materialized.get('https://atomicdata.dev/properties/name')).toBe(
      'Test Drive',
    );
    expect(materialized.get('https://atomicdata.dev/properties/write')).toEqual(
      [agentDID],
    );
    expect(materialized.get('https://atomicdata.dev/properties/read')).toEqual([
      agentDID,
    ]);
  });

  it('a folder genesis carries parent + class metadata', async ({ expect }) => {
    const { store, postCommitSpy } = await testStore();
    const parent = 'did:ad:drive-parent';

    const folder = await store.newResource({
      isA: core.classes.property,
      parent,
      propVals: { [core.properties.name]: 'Folder' },
    });
    expect(await folder.save()).toBe('persisted');

    const genesis = postCommitSpy.mock.calls[0][0] as Commit;
    const materialized = new Resource(genesis.subject);
    materialized.importLoroUpdate(genesis.loroUpdate!);

    expect(materialized.get('https://atomicdata.dev/properties/parent')).toBe(
      'atomic:drive-parent',
    );
    expect(materialized.get('https://atomicdata.dev/properties/isA')).toEqual([
      core.classes.property,
    ]);
    expect(materialized.get('https://atomicdata.dev/properties/name')).toBe(
      'Folder',
    );
  });

  it('saves Loro-doc changes made outside set() (e.g. the rich text editor)', async ({
    expect,
  }) => {
    const { store, postCommitSpy } = await testStore();

    const doc = await store.newResource({
      isA: 'https://atomicdata.dev/classes/DocumentV2',
      propVals: { [core.properties.name]: 'My Doc' },
      noParent: true,
    });
    expect(await doc.save()).toBe('persisted');
    expect(postCommitSpy.mock.calls.length).toBe(1);
    const genesis = postCommitSpy.mock.calls[0][0] as Commit;

    // Simulate loro-prosemirror: mutate the LoroDoc directly, then
    // signal the change the way `useLoroSync` does.
    const editorDoc = doc.getLoroDoc()!;
    editorDoc.getMap('doc').set('content', 'Hello world');
    doc.markDirty();
    expect(doc.hasUnsavedChanges()).toBe(true);

    expect(await doc.save()).toBe('persisted');
    expect(postCommitSpy.mock.calls.length).toBe(2);
    const delta = postCommitSpy.mock.calls[1][0] as Commit;
    expect(delta.loroUpdate!.length).toBeGreaterThan(4);

    // The out-of-band edit round-trips: genesis snapshot + delta.
    const materialized = new Resource(delta.subject);
    materialized.importLoroUpdate(genesis.loroUpdate!);
    materialized.importLoroUpdate(delta.loroUpdate!);
    expect(materialized.getLoroDoc()!.getMap('doc').toJSON()).toHaveProperty(
      'content',
      'Hello world',
    );
  });

  it('does not cache the just-saved commit as a store resource', async ({
    expect,
  }) => {
    /**
     * Commits are signed envelopes, not queryable resources.
     * After `save()`, the commit DID must not appear in `store.resources`
     * — UI reads author/date from the resource, not by fetching
     * `did:ad:commit:…`.
     */
    const { store, posted } = await testStore();

    const msg = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Message',
      propVals: { [core.properties.description]: 'hello chatroom' },
      noParent: true,
    });
    expect(await msg.save()).toBe('persisted');

    expect(posted.length).toBe(1);
    const commitDidSubject = `did:ad:commit:${posted[0].signature}`;
    expect(store.resources.has(commitDidSubject)).toBe(false);
  });
});

/**
 * Offline durability regressions. These assert on the OUTBOX and
 * clientDb plumbing (the contract that an offline `save()` persists
 * locally and survives a reload), so they wire a mock clientDb and
 * inspect what gets written — but the resource lifecycle still goes
 * through the public `newResource()` → `set()` → `save()` API.
 */
describe('offline persistence', () => {
  interface DbEntry {
    json: string;
    snapshot?: Uint8Array;
  }

  /** Attach an in-memory mock clientDb to a store; returns its backing map. */
  function attachMockClientDb(store: Store): Map<string, DbEntry> {
    const dbState = new Map<string, DbEntry>();
    (store as unknown as { clientDb: unknown }).clientDb = {
      isReady: true,
      isInitialized: true,
      initError: undefined,
      flush: async () => undefined,
      putResourceWithSnapshot: vi.fn(
        async (subject: string, json: string, snapshot?: Uint8Array) => {
          dbState.set(subject, { json, snapshot });
        },
      ),
      getResource: async (s: string) => dbState.get(s)?.json ?? null,
      getResourceWithSnapshot: async (s: string) => {
        const e = dbState.get(s);

        return { jsonAd: e?.json ?? null, snapshot: e?.snapshot };
      },
      getLoroSnapshot: async (s: string) => dbState.get(s)?.snapshot,
      waitForInit: async () => true,
      waitForReady: async () => true,
    };

    return dbState;
  }

  it('an offline save persists to clientDb and marks the outbox dirty', async ({
    expect,
  }) => {
    const { store } = await testStore();
    const dbState = attachMockClientDb(store);

    const doc = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Folder',
      propVals: { [core.properties.name]: 'OnlineName' },
      noParent: true,
    });
    await doc.save();
    const subject = doc.subject;

    store.setServerConnected(false);
    await doc.set(
      'https://atomicdata.dev/properties/name',
      'OfflineName',
      false,
    );
    expect(await doc.save()).toBe('offline');

    expect(dbState.get(subject)?.json).toContain('OfflineName');
    expect(store.outbox.hasPending(subject)).toBe(true);
  });

  it('a stale WS update does not clobber the offline edit in clientDb', async ({
    expect,
  }) => {
    const { store } = await testStore();
    const dbState = attachMockClientDb(store);

    const doc = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Folder',
      propVals: { [core.properties.name]: 'OnlineName' },
      noParent: true,
    });
    await doc.save();
    const subject = doc.subject;

    store.setServerConnected(false);
    await doc.set(
      'https://atomicdata.dev/properties/name',
      'OfflineName',
      false,
    );
    await doc.save();
    expect(dbState.get(subject)?.json).toContain('OfflineName');

    // A WS UPDATE arrives carrying the stale server state. The outbox
    // dirty bit must protect the local offline edit from being
    // overwritten in clientDb.
    const stale = new Resource(subject);
    stale.setStore(store);
    stale.applyHydratedValues(
      Object.entries({
        '@id': subject,
        [core.properties.isA]: ['https://atomicdata.dev/classes/Folder'],
        'https://atomicdata.dev/properties/name': 'OnlineName',
      }) as [string, never][],
    );
    stale.loading = false;
    stale.new = false;
    store.applyIncoming({
      subject,
      resource: stale,
      source: 'ws-sub-push',
    });
    await Promise.resolve();

    expect(
      dbState.get(subject)?.json,
      'clientDb was overwritten with stale server state — offline edit lost',
    ).toContain('OfflineName');
  });

  it('the Loro subscriber does not mark dirty mid-edit while offline', async ({
    expect,
  }) => {
    // Regression: `pendingDirtyCount` must not rise from a bare `set()`
    // before `save()` runs `saveOffline`. Otherwise the e2e
    // `set → wait(pendingDirtyCount>0) → reload` races ahead of the
    // clientDb write and loses the edit.
    const { store } = await testStore();
    attachMockClientDb(store);

    const doc = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Folder',
      propVals: { [core.properties.name]: 'Online' },
      noParent: true,
    });
    await doc.save();

    store.setServerConnected(false);
    const baseline = store.getSyncStatus().pendingDirtyCount;

    // Mutate WITHOUT saving — the subscriber must stay quiet offline.
    await doc.set(
      'https://atomicdata.dev/properties/name',
      'OfflineEdit',
      false,
    );
    expect(store.getSyncStatus().pendingDirtyCount).toBe(baseline);

    // Saving raises it.
    await doc.save();
    expect(store.getSyncStatus().pendingDirtyCount).toBeGreaterThan(baseline);
  });
});
