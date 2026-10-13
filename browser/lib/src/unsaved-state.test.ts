/**
 * What "has unsaved changes" means, pinned per scenario.
 *
 * `Resource.hasUnsavedChanges()` answers "did the user change this resource
 * in this session, and has that change not reached the server yet". The UI
 * reads it through `store.getSaveState()` (`kind: 'dirty'`), and the store
 * reads it to decide whether an incoming copy may overwrite local state.
 *
 * The save cursor (`hasOpsPastSaveCursor()`) and the pending genesis look
 * like they answer the same question, but they do not, and the last block of
 * tests shows where they disagree. Deriving the flag from them would change
 * what the UI shows.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { core } from './ontologies/core.js';
import { Resource, ResourceEvents } from './resource.js';
import { testStore } from './test-store.js';
import type { Store } from './store.js';

const FOLDER = 'https://atomicdata.dev/classes/Folder';
const DRIVE = 'https://atomicdata.dev/classes/Drive';

afterEach(() => vi.restoreAllMocks());

/** A local database that accepts writes: an offline save is only safe, and
 *  only reported as `'offline'`, once it is stored on this device. */
function localDatabase(store: Store): void {
  vi.spyOn(store, 'getClientDb').mockReturnValue({
    unsupportedEnvironment: false,
    putResourceWithSnapshot: vi.fn().mockResolvedValue(undefined),
  } as unknown as NonNullable<ReturnType<Store['getClientDb']>>);
}

async function savedFolder(name = 'Saved') {
  const ctx = await testStore();
  const resource = await ctx.store.newResource({
    isA: FOLDER,
    parent: 'https://example.com/drive',
    propVals: { [core.properties.name]: name },
  });
  await expect(resource.save()).resolves.toBe('persisted');

  return { ...ctx, resource };
}

describe('unsaved state', () => {
  it('edit: set() marks the resource unsaved', async () => {
    const { store, resource } = await savedFolder();
    expect(resource.hasUnsavedChanges()).toBe(false);
    expect(store.getSaveState(resource).kind).toBe('idle');

    await resource.set(core.properties.name, 'Edited', false);

    expect(resource.hasUnsavedChanges()).toBe(true);
    expect(store.getSaveState(resource).kind).toBe('dirty');
    store.setServerConnected(false);
  });

  it('save: an acknowledged save clears it', async () => {
    const { store, resource, posted } = await savedFolder();
    await resource.set(core.properties.name, 'Edited', false);
    const before = posted.length;

    await expect(resource.save()).resolves.toBe('persisted');

    expect(posted.length).toBe(before + 1);
    expect(resource.hasUnsavedChanges()).toBe(false);
    expect(resource.hasOpsPastSaveCursor()).toBe(false);
    expect(store.outbox.hasPending(resource.subject)).toBe(false);
    expect(store.getSaveState(resource).kind).toBe('idle');
    store.setServerConnected(false);
  });

  it('failed save: a server refusal keeps it and reports the error', async () => {
    const { store, resource, postCommitSpy } = await savedFolder();
    await resource.set(core.properties.name, 'Refused', false);
    const refusal = new Error('Unauthorized: no write rights in parent');
    postCommitSpy.mockRejectedValue(refusal);

    await expect(resource.save()).rejects.toBe(refusal);

    expect(resource.hasUnsavedChanges()).toBe(true);
    expect(resource.hasOpsPastSaveCursor()).toBe(true);
    expect(resource.commitError).toBe(refusal);
    // The entry stays queued for retry, but the refusal outranks it in the
    // status: the change is not on its way until the error is resolved.
    expect(store.outbox.hasPending(resource.subject)).toBe(true);
    expect(store.getSaveState(resource)).toMatchObject({
      kind: 'error',
      error: refusal.message,
    });
    store.setServerConnected(false);
  });

  it('offline: the edit stays unsaved and is shown as queued', async () => {
    const { store, resource } = await savedFolder();
    localDatabase(store);
    store.setServerConnected(false);
    await resource.set(core.properties.name, 'Offline edit', false);

    await expect(resource.save()).resolves.toBe('offline');

    expect(resource.hasUnsavedChanges()).toBe(true);
    expect(store.outbox.hasPending(resource.subject)).toBe(true);
    expect(store.getSaveState(resource)).toMatchObject({
      kind: 'queued',
      reason: 'offline',
    });
  });

  it('genesis: a created-but-unsaved resource is not shown as unsaved, yet save() still sends it', async () => {
    const { store, posted } = await testStore();
    const resource = await store.newResource({
      isA: DRIVE,
      noParent: true,
      propVals: { [core.properties.name]: 'Placeholder' },
    });

    // A table placeholder row is created like this on mount. It must not
    // read as an unsaved edit, and discarding it must not POST anything.
    expect(resource.hasUnsavedChanges()).toBe(false);
    expect(resource.hasOpsPastSaveCursor()).toBe(false);
    expect(store.getSaveState(resource).kind).toBe('idle');
    expect(posted).toHaveLength(0);

    await expect(resource.save()).resolves.toBe('persisted');

    expect(posted).toHaveLength(1);
    expect(posted[0].isGenesis).toBe(true);
    expect(resource.hasUnsavedChanges()).toBe(false);
    store.setServerConnected(false);
  });

  it('rich editor: a direct Loro edit counts only after markDirty()', async () => {
    const { store, resource, posted } = await savedFolder();
    const doc = resource.getLoroDoc()!;
    const localChange = vi.fn();
    resource.on(ResourceEvents.LocalChange, localChange);

    // The editor (loro-prosemirror) writes into the doc itself.
    doc.getMap('properties').set(core.properties.description, 'Typed');
    doc.commit();

    // The ops are there, but no one has claimed them as a user edit yet.
    // An AI edit held for review sits in exactly this state.
    expect(resource.hasOpsPastSaveCursor()).toBe(true);
    expect(resource.hasUnsavedChanges()).toBe(false);

    // `useLoroSync` calls this from the doc's local-update subscription.
    resource.markDirty();

    expect(resource.hasUnsavedChanges()).toBe(true);
    expect(localChange).toHaveBeenCalled();
    expect(store.getSaveState(resource).kind).not.toBe('idle');

    const before = posted.length;
    await expect(resource.save()).resolves.toBe('persisted');
    expect(posted.length).toBe(before + 1);
    expect(resource.hasUnsavedChanges()).toBe(false);
    expect(resource.hasOpsPastSaveCursor()).toBe(false);
    store.setServerConnected(false);
  });
});

describe('why the save cursor is not the unsaved flag', () => {
  it('a reconciliation write moves the cursor but is not a user edit', async () => {
    const subject = 'https://example.com/unsaved-reconcile';
    const stub = new Resource(subject);
    stub.applyHydratedValues([[core.properties.incomplete, true]]);
    stub.getLoroDoc();

    const full = new Resource(subject);
    await full.set(core.properties.name, 'Full copy', false);
    full.loading = false;
    stub.merge(full);

    // `merge` drops the stub's `incomplete` marker with a local Loro op.
    expect(stub.get(core.properties.incomplete)).toBeUndefined();
    expect(stub.hasOpsPastSaveCursor()).toBe(true);
    expect(stub.hasUnsavedChanges()).toBe(false);
  });

  it('a new resource has edits but no cursor yet', async () => {
    const resource = new Resource('_new:unsaved-no-cursor', true);
    await resource.set(core.properties.name, 'Draft', false);

    // With no cursor, the next export is a full snapshot; the cursor has
    // nothing to compare against.
    expect(resource.hasOpsPastSaveCursor()).toBe(false);
    expect(resource.hasUnsavedChanges()).toBe(true);
  });

  it('a pending genesis is not an unsaved edit', async () => {
    const { store } = await testStore();
    const resource = await store.newResource({ isA: DRIVE, noParent: true });

    // `store.newResource` signs the genesis up front: the cursor is caught
    // up and the flag is clear, but save() still has work to do.
    expect(resource.hasUnsavedChanges()).toBe(false);
    expect(resource.hasOpsPastSaveCursor()).toBe(false);
    await expect(resource.save()).resolves.not.toBe('noop');
    store.setServerConnected(false);
  });
});
