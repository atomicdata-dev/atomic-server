import { describe, it, vi } from 'vitest';
import {
  core,
  commits,
  server,
  isAtomicIdentifier,
  isCommitSubject,
} from './index.js';
import { testStore, attachTestDb } from './test-store.js';

/**
 * Local-only drives (e.g. the demo workspace): resources save and
 * stamp lastCommit entirely client-side — nothing may ever be POSTed
 * or enrolled in the outbox.
 */
describe('Local-only drives', () => {
  it('waits for a readable root before asking for the server inventory', async ({
    expect,
  }) => {
    const { store } = await testStore();
    const drive = 'atomic:uploading-drive';
    const ws = {
      readyState: WebSocket.OPEN,
      resyncDrive: vi.fn(async () => {}),
      fetch: vi
        .fn()
        .mockRejectedValueOnce(new Error('Root not found yet'))
        .mockResolvedValue({}),
      driveInventory: vi.fn(async () => [{ subject: drive, vv: { peer: 1 } }]),
    };
    vi.spyOn(store, 'getWebSocketForSubject').mockReturnValue(ws as never);
    vi.spyOn(store, 'getClientDb').mockReturnValue({
      flush: vi.fn(async () => {}),
      getVersionVectorsForDrive: vi.fn(async () => ({ [drive]: { peer: 1 } })),
    } as never);
    vi.spyOn(store, 'subscribeWebSocket').mockImplementation(() => {});
    vi.useFakeTimers();

    try {
      const upload = store.syncDriveToServerAndVerify(drive);
      await vi.waitFor(() => expect(ws.fetch).toHaveBeenCalledTimes(1));
      expect(ws.driveInventory).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(2000);
      await upload;
      expect(ws.driveInventory).toHaveBeenCalledExactlyOnceWith(drive, '');
    } finally {
      vi.useRealTimers();
      vi.restoreAllMocks();
    }
  });
  it('saves the drive without POSTing or enrolling the outbox', async ({
    expect,
  }) => {
    const { store, posted } = await testStore();
    attachTestDb(store);

    const drive = await store.newResource({
      isA: server.classes.drive,
      noParent: true,
      propVals: { [core.properties.name]: 'Demo team' },
    });
    store.registerLocalOnlyDrive(drive.subject);

    const result = await drive.save();

    expect(result).toBe('persisted');
    expect(posted).toHaveLength(0);
    expect(store.outbox.size).toBe(0);
    expect(isAtomicIdentifier(drive.subject)).toBe(true);

    const lastCommit = String(drive.get(commits.properties.lastCommit));
    expect(isCommitSubject(lastCommit)).toBe(true);
    expect(store.resources.has(lastCommit)).toBe(false);
  });

  it('resolves children as local-only and stamps lastCommit locally', async ({
    expect,
  }) => {
    const { store, posted } = await testStore();
    attachTestDb(store);

    const drive = await store.newResource({
      isA: server.classes.drive,
      noParent: true,
      propVals: { [core.properties.name]: 'Demo team' },
    });
    store.registerLocalOnlyDrive(drive.subject);
    await drive.save();

    const doc = await store.newResource({
      parent: drive.subject,
      propVals: { [core.properties.name]: 'Welcome' },
    });

    expect(store.isLocalOnlySubject(doc.subject)).toBe(true);

    await doc.save();
    const first = String(doc.get(commits.properties.lastCommit));
    expect(isCommitSubject(first)).toBe(true);

    await doc.set(core.properties.name, 'Welcome aboard');
    await doc.save();
    const second = String(doc.get(commits.properties.lastCommit));

    expect(second).not.toBe(first);

    expect(posted).toHaveLength(0);
    expect(store.outbox.size).toBe(0);
  });

  it('leaves other drives untouched', async ({ expect }) => {
    const { store, posted } = await testStore();
    attachTestDb(store);

    const localDrive = await store.newResource({
      isA: server.classes.drive,
      noParent: true,
      propVals: { [core.properties.name]: 'Demo team' },
    });
    store.registerLocalOnlyDrive(localDrive.subject);
    await localDrive.save();

    // A resource outside the local-only drive still drains normally.
    const synced = await store.newResource({
      propVals: { [core.properties.name]: 'Synced' },
    });

    expect(store.isLocalOnlySubject(synced.subject)).toBe(false);

    await synced.save();

    expect(posted.length).toBeGreaterThan(0);
    expect(posted.every(commit => commit.subject !== localDrive.subject)).toBe(
      true,
    );
  });
});
