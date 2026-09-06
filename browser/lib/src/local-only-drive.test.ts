import { describe, it } from 'vitest';
import { core, commits, server } from './index.js';
import { testStore } from './test-store.js';

/**
 * Local-only drives (e.g. the demo workspace): resources save and
 * stamp lastCommit entirely client-side — nothing may ever be POSTed
 * or enrolled in the outbox.
 */
describe('Local-only drives', () => {
  it('saves the drive without POSTing or enrolling the outbox', async ({
    expect,
  }) => {
    const { store, posted } = await testStore();

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
    expect(drive.subject.startsWith('did:ad:')).toBe(true);

    const lastCommit = String(drive.get(commits.properties.lastCommit));
    expect(lastCommit.startsWith('did:ad:commit:')).toBe(true);
    expect(store.resources.has(lastCommit)).toBe(false);
  });

  it('resolves children as local-only and stamps lastCommit locally', async ({
    expect,
  }) => {
    const { store, posted } = await testStore();

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
    expect(first.startsWith('did:ad:commit:')).toBe(true);

    await doc.set(core.properties.name, 'Welcome aboard');
    await doc.save();
    const second = String(doc.get(commits.properties.lastCommit));

    expect(second).not.toBe(first);

    expect(posted).toHaveLength(0);
    expect(store.outbox.size).toBe(0);
  });

  it('leaves other drives untouched', async ({ expect }) => {
    const { store, posted } = await testStore();

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
