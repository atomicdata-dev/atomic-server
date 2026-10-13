import { describe, expect as globalExpect, it, vi } from 'vitest';
import type { Agent } from './agent.js';
import type { ClientDbWorker } from './client-db.js';
import { Store, StoreEvents } from './store.js';
import { core } from './ontologies/core.js';
import { testStore } from './test-store.js';

const DRIVE = 'did:ad:personal';
const OTHER = 'did:ad:other';
const REFUSAL = `Drive ${DRIVE} is not enrolled for sync on this node.`;

function storeWithLocalCopy() {
  const store = new Store({ serverUrl: 'http://localhost:9883' });
  vi.spyOn(store, 'getAgent').mockReturnValue({} as Agent);
  vi.spyOn(store, 'getClientDb').mockReturnValue({
    isReady: true,
    waitForInit: async () => true,
  } as unknown as ClientDbWorker);

  return store;
}

describe('a drive the server refuses as not enrolled', () => {
  it('is reported as refused, and only for that drive', ({ expect }) => {
    const store = new Store({ serverUrl: 'http://localhost:9883' });
    expect(store.isDriveRefusedByServer(DRIVE)).toBe(false);

    store.failDriveSync(DRIVE, REFUSAL);

    expect(store.isDriveRefusedByServer(DRIVE)).toBe(true);
    expect(store.isDriveRefusedByServer(OTHER)).toBe(false);
  });

  it('is not refused for any other sync error', ({ expect }) => {
    const store = new Store({ serverUrl: 'http://localhost:9883' });
    store.failDriveSync(
      DRIVE,
      `Drive ${DRIVE} has reached its storage quota on this node.`,
    );

    expect(store.isDriveRefusedByServer(DRIVE)).toBe(false);
  });

  it('can be made local without the server, dropping its refused writes', async ({
    expect,
  }) => {
    const store = storeWithLocalCopy();
    // No websocket and no server inventory: the refused path must not need them.
    vi.spyOn(store, 'getDefaultWebSocket').mockReturnValue(undefined);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const outbox = (store as any).outbox;
    outbox.markDirty(DRIVE);
    store.failDriveSync(DRIVE, REFUSAL);

    await store.makeDriveLocal(DRIVE);

    expect(store.isLocalOnlyDrive(DRIVE)).toBe(true);
    expect(store.isDriveRefusedByServer(DRIVE)).toBe(false);
    expect(outbox.size).toBe(0);
    expect(store.getSyncStatus().lastDriveSyncError).toBeUndefined();
  });

  it('still verifies the local copy for a drive the server hosts', async ({
    expect,
  }) => {
    const store = storeWithLocalCopy();
    vi.spyOn(store, 'getDefaultWebSocket').mockReturnValue(undefined);

    // Verifying needs the server's inventory, so without a socket it stops.
    await expect(store.makeDriveLocal(DRIVE)).rejects.toThrow(
      'Connect to a server before disconnecting this workspace.',
    );
    expect(store.isLocalOnlyDrive(DRIVE)).toBe(false);
  });

  it('reports a refused drive once, not once per resource', ({ expect }) => {
    const store = new Store({ serverUrl: 'http://localhost:9883' });
    const seen: string[] = [];
    store.on(StoreEvents.Error, e => {
      seen.push(e.message);
    });
    const notify = (subject: string, message: string) =>
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (store as any).notifyBlockedSync(subject, message);

    notify('did:ad:canvas', REFUSAL);
    notify('did:ad:comments', REFUSAL);
    notify('did:ad:comments2', REFUSAL);

    expect(seen).toHaveLength(1);
    expect(seen[0]).toContain('does not host this workspace');
    expect(seen[0]).toContain('kept on this device');
  });

  it('still reports every other blocked write', ({ expect }) => {
    const store = new Store({ serverUrl: 'http://localhost:9883' });
    const seen: string[] = [];
    store.on(StoreEvents.Error, e => {
      seen.push(e.message);
    });
    const notify = (subject: string, message: string) =>
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (store as any).notifyBlockedSync(subject, message);

    notify('did:ad:a', 'Unauthorized: no write rights in parent');
    notify('did:ad:b', 'Unauthorized: no write rights in parent');

    expect(seen).toHaveLength(2);
    expect(seen[0]).toContain('Not retrying');
  });
});

describe('the app resolving a refused drive before it is reported', () => {
  const notify = (store: Store, subject: string, message = REFUSAL) =>
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (store as any).notifyBlockedSync(subject, message);
  const settle = () => new Promise(resolve => setTimeout(resolve, 0));

  function watch(store: Store) {
    const errors: string[] = [];
    store.on(StoreEvents.Error, e => {
      errors.push(e.message);
    });

    return errors;
  }

  it('reports nothing when the handler resolved the drive', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'http://localhost:9883' });
    const errors = watch(store);
    const handler = vi.fn(async () => true);
    store.setRefusedDriveHandler(handler);

    notify(store, 'did:ad:canvas');
    await settle();

    expect(handler).toHaveBeenCalledExactlyOnceWith(DRIVE, REFUSAL);
    expect(errors).toEqual([]);
  });

  it.each([
    ['declines', async () => false],
    [
      'throws',
      async () => {
        throw new Error('lookup failed');
      },
    ],
  ])('reports the refusal when the handler %s', async (_, impl) => {
    const expect = globalExpect;
    const store = new Store({ serverUrl: 'http://localhost:9883' });
    const errors = watch(store);
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    store.setRefusedDriveHandler(impl);

    notify(store, 'did:ad:canvas');
    await settle();

    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('does not host this workspace');
  });

  it('asks about a drive once, however many of its writes are refused', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'http://localhost:9883' });
    const errors = watch(store);
    const handler = vi.fn(async () => false);
    store.setRefusedDriveHandler(handler);

    notify(store, 'did:ad:a');
    notify(store, 'did:ad:b');
    await settle();
    notify(store, 'did:ad:c');
    await settle();

    expect(handler).toHaveBeenCalledTimes(1);
    expect(errors).toHaveLength(1);
  });

  it('does not ask for a refusal that names no drive', async ({ expect }) => {
    const store = new Store({ serverUrl: 'http://localhost:9883' });
    const errors = watch(store);
    const handler = vi.fn(async () => true);
    store.setRefusedDriveHandler(handler);

    notify(store, 'did:ad:a', 'is not enrolled for sync on this node');
    await settle();

    expect(handler).not.toHaveBeenCalled();
    expect(errors).toHaveLength(1);
  });

  it('reports as before once the handler is removed', ({ expect }) => {
    const store = new Store({ serverUrl: 'http://localhost:9883' });
    const errors = watch(store);
    const handler = vi.fn(async () => true);
    store.setRefusedDriveHandler(handler)();

    notify(store, 'did:ad:a');

    expect(handler).not.toHaveBeenCalled();
    expect(errors).toHaveLength(1);
  });

  it('parks a refused drive in browser-only mode without losing its data or repeating the report', async ({
    expect,
  }) => {
    const { store, postCommitSpy } = await testStore();
    vi.spyOn(store, 'getClientDb').mockReturnValue({
      isReady: true,
      waitForInit: async () => true,
    } as unknown as ClientDbWorker);
    const drive = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      noParent: true,
      propVals: { [core.properties.name]: 'Phone drive' },
    });
    const refusal = `Drive ${drive.subject} is not enrolled for sync on this node.`;
    postCommitSpy.mockRejectedValue(new Error(refusal));
    const errors = watch(store);
    const failing: string[] = [];
    store.on(StoreEvents.CommitRepeatedlyFailing, f => {
      failing.push(f.error.message);
    });
    const handler = vi.fn(async (refused: string) => {
      await store.makeDriveLocal(refused);

      return true;
    });
    store.setRefusedDriveHandler(handler);

    await drive.save().catch(() => undefined);

    // The same genesis, drained again and again until it is parked.
    for (let i = 0; i < 12 && !store.isLocalOnlyDrive(drive.subject); i++) {
      const entry = store.outbox.getEntry(drive.subject);
      if (entry) entry.lastAttemptAt = 0;
      await store.syncDirtyResources();
      await settle();
    }

    expect(store.isLocalOnlyDrive(drive.subject)).toBe(true);
    expect(handler).toHaveBeenCalledTimes(1);
    expect(errors).toEqual([]);
    expect(failing).toEqual([]);
    // Nothing is queued for the node any more, and it is not asked again.
    expect(store.outbox.size).toBe(0);
    const attempts = postCommitSpy.mock.calls.length;
    await store.syncDirtyResources();
    expect(postCommitSpy).toHaveBeenCalledTimes(attempts);
    // The drive is still here, with what was written to it.
    expect(store.resources.get(drive.subject)).toBe(drive);
    expect(drive.get(core.properties.name)).toBe('Phone drive');
    store.setServerConnected(false);
  });

  it('still reports a repeatedly failing refusal that the handler leaves alone', async ({
    expect,
  }) => {
    const { store, postCommitSpy } = await testStore();
    const drive = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      noParent: true,
    });
    postCommitSpy.mockRejectedValue(
      new Error(
        `Drive ${drive.subject} is not enrolled for sync on this node.`,
      ),
    );
    const errors = watch(store);
    const failing: string[] = [];
    store.on(StoreEvents.CommitRepeatedlyFailing, f => {
      failing.push(f.error.message);
    });
    store.setRefusedDriveHandler(async () => false);

    await drive.save().catch(() => undefined);

    for (let i = 0; i < 10; i++) {
      const entry = store.outbox.getEntry(drive.subject);
      if (entry) entry.lastAttemptAt = 0;
      await store.syncDirtyResources();
      await settle();
    }

    expect(failing).toHaveLength(1);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('does not host this workspace');
    expect(store.outbox.hasPending(drive.subject)).toBe(true);
    expect(store.isLocalOnlyDrive(drive.subject)).toBe(false);
    store.setServerConnected(false);
  });
});
