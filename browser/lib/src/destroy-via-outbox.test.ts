import { afterEach, describe, expect, it, vi } from 'vitest';
import { Agent } from './agent.js';
import { CommitBuilder } from './commit.js';
import { JSCryptoProvider } from './CryptoProvider.js';
import { core } from './ontologies/core.js';
import { server } from './ontologies/server.js';
import { LocalOutbox, isSettledDestroyErrorMessage } from './local-outbox.js';
import { attachTestDb, testStore } from './test-store.js';
import type { ClientDbWorker } from './client-db.js';

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
  // `test-setup.ts` relies on this flag to keep the Store off a real WS.
  localStorage.setItem('ws-disconnected', '1');
});

/** A saved (server-acknowledged) drive: `new` is false, the outbox is empty. */
async function savedDrive(name = 'Doomed') {
  const harness = await testStore();
  const doc = await harness.store.newResource({
    isA: server.classes.drive,
    noParent: true,
    propVals: { [core.properties.name]: name },
  });
  await doc.save();
  expect(harness.store.outbox.hasPending(doc.subject)).toBe(false);
  harness.postCommitSpy.mockClear();

  return { ...harness, doc };
}

describe('Resource.destroy() through the outbox', () => {
  it('online: POSTs one destroy commit and removes the resource', async () => {
    const { store, doc, postCommitSpy } = await savedDrive();

    await expect(doc.destroy()).resolves.toBeUndefined();

    expect(postCommitSpy).toHaveBeenCalledTimes(1);
    const commit = postCommitSpy.mock.calls[0][0];
    expect(commit.destroy).toBe(true);
    expect(commit.subject).toBe(doc.subject);
    expect(commit.loroUpdate).toBeUndefined();
    expect(store.resources.has(doc.subject)).toBe(false);
    expect(store.outbox.hasPending(doc.subject)).toBe(false);
    expect(store.getSyncStatus().pendingDirtyCount).toBe(0);
    store.setServerConnected(false);
  });

  it('offline: queues the signed destroy, survives a reload, drains once on reconnect', async () => {
    const { store, doc, agentDID, postCommitSpy } = await savedDrive();
    store.setServerConnected(false);

    await expect(doc.destroy()).resolves.toBeUndefined();

    // Removed locally at once, nothing sent, the envelope is queued.
    expect(postCommitSpy).not.toHaveBeenCalled();
    expect(store.resources.has(doc.subject)).toBe(false);
    const queued = store.outbox.getEntry(doc.subject)?.signedDestroy;
    expect(queued?.destroy).toBe(true);
    expect(queued?.signature).toBeTruthy();
    expect(store.hasPendingDestroy(doc.subject)).toBe(true);

    // Simulated reload: a fresh outbox hydrating the same agent's storage
    // must hold the SAME signed envelope (a destroy cannot be re-signed —
    // the resource it names is already gone locally).
    store.outbox.flush();
    const reloaded = new LocalOutbox();
    reloaded.rebind(agentDID);
    const restored = reloaded.getEntry(doc.subject)?.signedDestroy;
    expect(restored?.destroy).toBe(true);
    expect(restored?.subject).toBe(doc.subject);
    expect(restored?.signature).toBe(queued!.signature);
    expect(restored?.signer).toBe(agentDID);

    // Reconnect: the drain POSTs it exactly once and drops the entry.
    store.setServerConnected(true);
    await store.syncDirtyResources();

    expect(postCommitSpy).toHaveBeenCalledTimes(1);
    expect(postCommitSpy.mock.calls[0][0].signature).toBe(queued!.signature);
    expect(store.outbox.hasPending(doc.subject)).toBe(false);
    expect(store.hasPendingDestroy(doc.subject)).toBe(false);
    expect(store.resources.has(doc.subject)).toBe(false);
    store.setServerConnected(false);
  });

  it('offline create + destroy: POSTs neither the genesis nor the destroy', async () => {
    const { store, postCommitSpy } = await testStore();
    attachTestDb(store);
    store.setServerConnected(false);

    const doc = await store.newResource({
      isA: server.classes.drive,
      noParent: true,
      propVals: { [core.properties.name]: 'Never synced' },
    });
    await expect(doc.save()).resolves.toBe('offline');
    expect(store.outbox.getEntry(doc.subject)?.signedGenesis).toBeTruthy();

    await expect(doc.destroy()).resolves.toBeUndefined();
    expect(store.resources.has(doc.subject)).toBe(false);
    // Both envelopes sit on the entry until the drain resolves them.
    const entry = store.outbox.getEntry(doc.subject);
    expect(entry?.signedGenesis).toBeTruthy();
    expect(entry?.signedDestroy).toBeTruthy();

    store.setServerConnected(true);
    await store.syncDirtyResources();

    expect(postCommitSpy).not.toHaveBeenCalled();
    expect(store.outbox.hasPending(doc.subject)).toBe(false);
    expect(store.resources.has(doc.subject)).toBe(false);
    expect(store.getSyncStatus().pendingDirtyCount).toBe(0);
    store.setServerConnected(false);
  });

  it('a newResource that was never saved is dropped without a POST', async () => {
    const { store, postCommitSpy } = await testStore();
    const doc = await store.newResource({
      isA: server.classes.drive,
      noParent: true,
      propVals: { [core.properties.name]: 'Placeholder' },
    });
    // Genesis is parked on the resource until the first `save()`.
    expect(store.outbox.hasPending(doc.subject)).toBe(false);

    await expect(doc.destroy()).resolves.toBeUndefined();
    await store.syncDirtyResources();

    expect(postCommitSpy).not.toHaveBeenCalled();
    expect(store.resources.has(doc.subject)).toBe(false);
    expect(store.outbox.hasPending(doc.subject)).toBe(false);
    store.setServerConnected(false);
  });

  it('online: a server refusal rejects destroy() and keeps the delete queued', async () => {
    const { store, doc, postCommitSpy } = await savedDrive();
    const error = new Error(
      'No https://atomicdata.dev/properties/write right has been found for did:ad:agent:x in its parents',
    );
    postCommitSpy.mockRejectedValue(error);

    await expect(doc.destroy()).rejects.toBe(error);

    expect(postCommitSpy).toHaveBeenCalledTimes(1);
    // Not acknowledged: the entry stays for the outbox's backoff / blocking
    // handling, and the local removal is not undone by the refusal.
    expect(store.outbox.getEntry(doc.subject)?.signedDestroy).toBeTruthy();
    expect(store.outbox.getEntry(doc.subject)?.failures).toBe(1);
    expect(store.resources.has(doc.subject)).toBe(false);
    store.setServerConnected(false);
  });

  it('online: a transport failure resolves as queued and flips the store offline', async () => {
    const { store, doc, postCommitSpy } = await savedDrive();
    postCommitSpy.mockRejectedValue(new TypeError('Failed to fetch'));

    await expect(doc.destroy()).resolves.toBeUndefined();

    expect(store.serverConnected).toBe(false);
    expect(store.outbox.getEntry(doc.subject)?.signedDestroy).toBeTruthy();
    expect(store.resources.has(doc.subject)).toBe(false);
  });

  it.each([
    'Destroy commit for did:ad:x was already applied here; refusing replay',
    "Destroy commit for did:ad:x (created 2) predates the resource's genesis (3); refusing replay",
    'Commit for did:ad:x has is_genesis: false, but the resource does not exist yet.',
  ])('"%s" counts as acknowledged: entry dropped, no retry', async message => {
    const { store, doc, postCommitSpy } = await savedDrive();
    postCommitSpy.mockRejectedValue(new Error(message));
    const notifyError = vi.spyOn(store, 'notifyError');

    await expect(doc.destroy()).resolves.toBeUndefined();

    expect(postCommitSpy).toHaveBeenCalledTimes(1);
    expect(store.outbox.hasPending(doc.subject)).toBe(false);
    expect(store.resources.has(doc.subject)).toBe(false);
    expect(notifyError).not.toHaveBeenCalled();
    store.setServerConnected(false);
  });

  it('does not resurrect a destroyed-but-unacked resource from a push or a fetch', async () => {
    const { store, doc } = await savedDrive();
    store.setServerConnected(false);
    await doc.destroy();
    expect(store.resources.has(doc.subject)).toBe(false);

    // A late WS push / SYNC frame for the subject.
    const pushed = store.applyIncoming({
      subject: doc.subject,
      source: 'ws-sub-push',
      loroBytes: doc.getLoroDoc()!.export({ mode: 'snapshot' }),
      commitId: 'did:ad:commit:someoneElse',
    });
    expect(pushed).toBe('deduped');
    expect(store.resources.has(doc.subject)).toBe(false);

    // A fetch result that raced the delete.
    const fetched = store.applyIncoming({
      subject: doc.subject,
      source: 'http-fetch',
      resource: doc,
    });
    expect(fetched).toBe('deduped');
    expect(store.resources.has(doc.subject)).toBe(false);

    // A stale OPFS row the worker had not yet tombstoned.
    expect(
      store.hydrateResourceFromJsonAd(
        doc.subject,
        JSON.stringify({
          '@id': doc.subject,
          [core.properties.name]: 'Back from the dead',
        }),
      ),
    ).toBe(true);
    expect(store.resources.has(doc.subject)).toBe(false);
  });

  it('excludes a subject with a pending destroy from the drive VV', async () => {
    const { store, doc } = await savedDrive('Drive');
    const child = await store.newResource({
      parent: doc.subject,
      propVals: { [core.properties.name]: 'Child' },
    });
    await child.save();
    store.setServerConnected(false);

    // Pretend OPFS still lists the child (the tombstone write is async).
    (store as unknown as { clientDb: ClientDbWorker }).clientDb = {
      isReady: true,
      getVersionVectorsForDrive: async () => ({
        [child.subject]: { '1': 1 },
      }),
      removeResource: async () => undefined,
    } as unknown as ClientDbWorker;

    await child.destroy();
    const state = await store.computeDriveSyncState(doc.subject);

    expect(Object.keys(state.resources)).not.toContain(child.subject);
    expect(Object.keys(state.resources)).toContain(doc.subject);
  });
});

describe('LocalOutbox destroy envelopes', () => {
  async function signedDestroy(subject: string) {
    const keys = await Agent.generateKeyPair();
    const agentDID = `did:ad:agent:${keys.publicKey}`;
    const agent = new Agent(new JSCryptoProvider(keys.privateKey), agentDID);
    const builder = new CommitBuilder(subject);
    builder.setDestroy(true);

    return { commit: await builder.sign(agent), agentDID };
  }

  it('setDestroyCommit keeps the entry across clearDirty; clearDestroy drops it whole', async () => {
    const outbox = new LocalOutbox();
    const subject = 'did:ad:doomed';
    const { commit } = await signedDestroy(subject);

    outbox.markDirty(subject);
    outbox.setBaseVersion(subject, 'AAAA');
    outbox.setDestroyCommit(subject, commit);

    const entry = outbox.getEntry(subject)!;
    expect(entry.signedDestroy).toBe(commit);
    // No Loro delta is left to replay for a subject that is going away.
    expect(entry.baseVersion).toBeUndefined();

    outbox.clearDirty(subject);
    expect(outbox.getEntry(subject)?.signedDestroy).toBe(commit);

    outbox.clearDestroy(subject);
    expect(outbox.hasPending(subject)).toBe(false);
  });

  it('setDestroyCommit re-arms a blocked entry', async () => {
    const outbox = new LocalOutbox();
    const subject = 'did:ad:blocked';
    const { commit } = await signedDestroy(subject);
    outbox.markDirty(subject);
    const entry = outbox.getEntry(subject)!;
    entry.blocked = true;
    entry.failures = 8;

    outbox.setDestroyCommit(subject, commit);

    expect(entry.blocked).toBe(false);
    expect(entry.failures).toBe(0);
    expect(outbox.nextDueAt()).toBe(0);
  });

  it('persists and rehydrates the signed destroy under the agent namespace', async () => {
    const subject = 'did:ad:persisted';
    const { commit, agentDID } = await signedDestroy(subject);

    const outbox = new LocalOutbox();
    outbox.rebind(agentDID);
    outbox.setDestroyCommit(subject, commit);
    outbox.flush();

    const reloaded = new LocalOutbox();
    reloaded.rebind(agentDID);
    const restored = reloaded.getEntry(subject)?.signedDestroy;
    expect(restored).toBeDefined();
    expect(restored?.destroy).toBe(true);
    expect(restored?.subject).toBe(subject);
    expect(restored?.signature).toBe(commit.signature);
    expect(restored?.signer).toBe(agentDID);
    expect(restored?.createdAt).toBe(commit.createdAt);

    // Another identity never sees it.
    const other = new LocalOutbox();
    other.rebind('did:ad:agent:someoneElse');
    expect(other.hasPending(subject)).toBe(false);
  });

  it('discard forgets every queued write for the subject', async () => {
    const outbox = new LocalOutbox();
    const subject = 'did:ad:discarded';
    const { commit } = await signedDestroy(subject);
    outbox.setGenesisCommit(subject, { ...commit, destroy: undefined });
    outbox.markDirty(subject);

    outbox.discard(subject);

    expect(outbox.hasPending(subject)).toBe(false);
    expect(outbox.size).toBe(0);
  });

  it('classifies only the "already gone" server answers as settled', () => {
    expect(
      isSettledDestroyErrorMessage(
        'Destroy commit for did:ad:x was already applied here; refusing replay',
      ),
    ).toBe(true);
    expect(
      isSettledDestroyErrorMessage(
        "Destroy commit for did:ad:x (created 1) predates the resource's genesis (2); refusing replay",
      ),
    ).toBe(true);
    expect(
      isSettledDestroyErrorMessage(
        'Commit for did:ad:x has is_genesis: false, but the resource does not exist yet.',
      ),
    ).toBe(true);
    expect(
      isSettledDestroyErrorMessage(
        'No https://atomicdata.dev/properties/write right has been found',
      ),
    ).toBe(false);
    expect(isSettledDestroyErrorMessage('Failed to fetch')).toBe(false);
  });
});
