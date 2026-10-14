import { afterEach, describe, expect, it, vi } from 'vitest';
import { core } from './ontologies/core.js';
import { attachTestDb, testStore } from './test-store.js';
import { decodeB64, encodeB64 } from './base64.js';
import { LoroLoader } from './loro-loader.js';

afterEach(() => vi.restoreAllMocks());

describe('save receipts', () => {
  it('does not retry an accepted genesis when receipt bookkeeping fails', async () => {
    const { store, posted } = await testStore();
    const doc = await store.newResource({ noParent: true });
    vi.spyOn(doc.__internalObject, 'recordServerAcceptance').mockImplementation(
      () => {
        throw new Error('receipt encoding failed');
      },
    );
    await doc.save();
    expect(store.outbox.getEntry(doc.subject)?.signedGenesis).toBeUndefined();
    await store.syncDirtyResources();
    expect(posted.filter(commit => commit.isGenesis)).toHaveLength(1);
    store.setServerConnected(false);
  });
  it('names the acknowledged server and version without claiming a local copy', async () => {
    const { store, posted } = await testStore();
    const doc = await store.newResource({ noParent: true });
    const receipt = await doc.saveWithReceipt();

    expect(receipt).toMatchObject({
      status: 'persisted',
      subject: doc.subject,
      server: { endpoint: 'https://example.com/commit' },
    });
    expect(receipt.local).toBeUndefined();
    expect(receipt.server?.commit).toContain(posted.at(-1)!.signature);
    expect(receipt.server?.version).toBe(doc.getEncodedSaveCursor());
    store.setServerConnected(false);
  });

  it.each([false, true])(
    'handles a disconnect before the drain attempts the save (online required: %s)',
    async requireOnlineWrites => {
      const { store, posted } = await testStore({ requireOnlineWrites });
      const { records } = attachTestDb(store);
      const doc = await store.newResource({ noParent: true });
      vi.spyOn(store, 'syncDirtyResources').mockImplementation(async () => {
        store.setServerConnected(false);
      });
      const saving = doc.saveWithReceipt();

      if (requireOnlineWrites) {
        await expect(saving).rejects.toThrow('still queued');
      } else {
        const receipt = await saving;
        expect(receipt.status).toBe('offline');
        expect(receipt.local).toBeDefined();
        expect(receipt.server).toBeUndefined();
        expect(records.get(doc.subject)?.snapshot?.length).toBeGreaterThan(0);
      }

      expect(posted).toHaveLength(0);
      expect(store.outbox.getEntry(doc.subject)?.signedGenesis).toBeDefined();
    },
  );

  it('does not persist an interrupted save into another identity', async () => {
    const { store } = await testStore();
    attachTestDb(store);
    const doc = await store.newResource({ noParent: true });
    let newer: ReturnType<typeof attachTestDb> | undefined;
    vi.spyOn(store, 'syncDirtyResources').mockImplementation(async () => {
      store.setAgent(undefined);
      newer = attachTestDb(store);
      store.setServerConnected(false);
    });
    await expect(doc.saveWithReceipt()).rejects.toThrow('identity changed');
    expect(newer!.records.size).toBe(0);
  });

  it('reports a durable local-only copy independently of peer delivery', async () => {
    const { store, posted } = await testStore();
    const { records } = attachTestDb(store);
    const doc = await store.newResource({ noParent: true });
    store.registerLocalOnlyDrive(doc.subject);
    const receipt = await doc.saveWithReceipt();

    expect(receipt.status).toBe('persisted');
    expect(receipt.server).toBeUndefined();
    const reloaded = new LoroLoader.Loro.LoroDoc();
    reloaded.import(records.get(doc.subject)!.snapshot!);
    expect(receipt.local?.version).toBe(
      encodeB64(reloaded.oplogVersion().encode()),
    );
    expect(posted).toHaveLength(0);
    store.setServerConnected(false);
  });

  it('returns the version in the acknowledgement, excluding edits made during the request', async () => {
    const { store, postCommitSpy } = await testStore();
    const doc = await store.newResource({ noParent: true });
    await doc.save();
    await doc.set(core.properties.name, 'First edit');
    let entered!: () => void;
    const started = new Promise<void>(resolve => {
      entered = resolve;
    });
    let complete!: () => void;
    const response = new Promise<void>(resolve => {
      complete = resolve;
    });
    postCommitSpy.mockImplementationOnce(async commit => {
      entered();
      await response;

      return commit;
    });
    const saving = doc.saveWithReceipt();
    await started;
    await doc.set(core.properties.name, 'Later edit');
    complete();
    const receipt = await saving;
    const accepted = LoroLoader.Loro.VersionVector.decode(
      decodeB64(receipt.server!.version),
    );
    const current = doc.getLoroDoc()!.oplogVersion();
    expect(accepted.compare(current)).toBe(-1);
    expect(store.outbox.hasPending(doc.subject)).toBe(true);
    store.setServerConnected(false);
  });

  it('provides no durability receipt for a child waiting on its parent', async () => {
    const { store } = await testStore();
    const parent = await store.newResource({ noParent: true });
    parent.new = true;
    const child = await store.newResource({ parent: parent.subject });
    expect(await child.saveWithReceipt()).toEqual({
      status: 'queued',
      subject: child.subject,
    });
    store.setServerConnected(false);
  });

  it.each(['identity', 'database'] as const)(
    'rejects local completion after the %s session changes',
    async boundary => {
      const { store } = await testStore();
      attachTestDb(store);
      const doc = await store.newResource({ noParent: true });
      let entered!: () => void;
      const started = new Promise<void>(resolve => {
        entered = resolve;
      });
      let complete!: () => void;
      const response = new Promise<void>(resolve => {
        complete = resolve;
      });
      vi.spyOn(store, 'persistState').mockImplementationOnce(async () => {
        entered();
        await response;
      });
      const onDurable = vi.fn();
      const saving = doc.persistToClientDb(undefined, {
        required: true,
        onDurable,
      });
      const rejection = expect(saving).rejects.toThrow(
        'Identity or database changed during local persistence',
      );
      await started;

      if (boundary === 'identity') {
        const agent = store.getAgent();
        store.setAgent(undefined);
        store.setAgent(agent);
      } else {
        attachTestDb(store);
      }

      complete();
      await rejection;
      expect(onDurable).not.toHaveBeenCalled();
      store.setServerConnected(false);
    },
  );
});
