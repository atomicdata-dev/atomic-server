import { describe, expect, it, vi } from 'vitest';
import { testStore } from './test-store.js';
import { core } from './ontologies/core.js';
import { StoreEvents, type CommitLogEntry, type Store } from './store.js';
import { LoroLoader } from './loro-loader.js';

const outgoing = (store: Store, subject: string): CommitLogEntry[] =>
  store
    .getCommitLog()
    .filter(e => e.subject === subject && e.status === 'sent')
    .reverse();

const changed = (store: Store, entry: CommitLogEntry) =>
  (store.getCommitPropertySummaries(entry) ?? []).map(s => [
    s.property,
    s.changeType,
  ]);

describe('commit log property summaries', () => {
  it('waits for Loro without warning or caching an absent summary', async () => {
    const { store } = await testStore();
    const doc = await store.newResource({
      noParent: true,
      propVals: { [core.properties.name]: 'Saved title' },
    });
    await doc.save();
    const [entry] = outgoing(store, doc.subject);
    const loaded = vi.spyOn(LoroLoader, 'isLoaded').mockReturnValue(false);
    const module = vi
      .spyOn(LoroLoader, 'Loro', 'get')
      .mockImplementation(() => {
        throw new Error('Loro not initialized');
      });
    const warn = vi.spyOn(console, 'warn');
    let ready: (() => void) | undefined;
    const onReady = vi
      .spyOn(LoroLoader, 'onReady')
      .mockImplementation(callback => {
        ready = callback;

        return () => {};
      });
    const notify = vi.fn();
    const unsubscribe = store.on(StoreEvents.CommitLogChanged, notify);

    try {
      expect(store.getCommitPropertySummaries(entry)).toBeUndefined();
      expect(warn).not.toHaveBeenCalled();
    } finally {
      loaded.mockRestore();
      module.mockRestore();
      warn.mockRestore();
      onReady.mockRestore();
    }

    expect(ready).toBeDefined();
    ready!();
    expect(notify).toHaveBeenCalledWith(store.getCommitLog());
    unsubscribe();
    expect(changed(store, entry)).toContainEqual([
      core.properties.name,
      'changed',
    ]);
  });

  it('are computed on demand and show only what each commit changed', async () => {
    const { store } = await testStore();
    const drive = await store.createDrive('Home', { personal: true });
    const doc = await store.newResource({
      parent: drive.subject,
      propVals: {
        [core.properties.name]: 'first',
        [core.properties.description]: 'kept',
      },
    });
    await doc.save();
    await doc.set(core.properties.name, 'second', false);
    await doc.save();
    await doc.remove(core.properties.description);
    await doc.save();

    const [genesis, rename, removal] = outgoing(store, doc.subject);

    expect(genesis).toBeDefined();
    expect(changed(store, genesis)).toEqual(
      expect.arrayContaining([
        [core.properties.name, 'changed'],
        [core.properties.description, 'changed'],
      ]),
    );
    expect(changed(store, rename)).toEqual([[core.properties.name, 'changed']]);
    expect(store.getCommitPropertySummaries(rename)?.[0].value).toBe('second');
    expect(changed(store, removal)).toEqual([
      [core.properties.description, 'removed'],
    ]);
    // Asking again returns the same answer.
    expect(changed(store, rename)).toEqual([[core.properties.name, 'changed']]);
  });

  it('keeps no state for commits that left the log', async () => {
    const { store } = await testStore();
    const drive = await store.createDrive('Home', { personal: true });
    const doc = await store.newResource({
      parent: drive.subject,
      propVals: { [core.properties.name]: 'v0' },
    });
    await doc.save();

    for (let i = 1; i <= 60; i++) {
      await doc.set(core.properties.name, `v${i}`, false);
      await doc.save();
    }

    const internals = store as unknown as {
      _commitLogUpdates: Map<string, Uint8Array>;
    };
    const ids = new Set(store.getCommitLog().map(e => e.id));
    expect(store.getCommitLog()).toHaveLength(50);
    expect(
      [...internals._commitLogUpdates.keys()].every(id => ids.has(id)),
    ).toBe(true);
  });
});
