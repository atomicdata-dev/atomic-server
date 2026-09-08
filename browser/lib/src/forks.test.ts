import { describe, it } from 'vitest';
import { core, Resource } from './index.js';
import { forks } from './ontologies/forks.js';
import { diffFork, forkResource, isFork, mergeFork } from './forks.js';
import { testStore } from './test-store.js';

const BLOGPOST = 'https://atomicdata.dev/classes/BlogPost';
const DRIVE = 'https://atomicdata.dev/classes/Drive';
const DOCUMENT_V2 = 'https://atomicdata.dev/classes/DocumentV2';
const PUBLIC_AGENT = 'https://atomicdata.dev/agents/publicAgent';

describe('forks', () => {
  it('forks a resource into a fork that carries the content, the classes and a link home', async ({
    expect,
  }) => {
    const { store } = await testStore();

    const drive = await store.newResource({
      isA: DRIVE,
      noParent: true,
    });
    await drive.save();

    const original = await store.newResource({
      parent: drive.subject,
      isA: BLOGPOST,
      propVals: {
        [core.properties.name]: 'Cheese',
        [core.properties.description]: 'A post about cheese.',
      },
    });
    await original.save();

    const fork = await forkResource(store, original, drive.subject);

    expect(fork.subject).not.toBe(original.subject);
    expect(isFork(fork)).toBe(true);
    expect(isFork(original)).toBe(false);
    expect(fork.get(forks.properties.originalSubject)).toBe(original.subject);

    // Content and classes come along...
    expect(fork.get(core.properties.name)).toBe('Cheese');
    expect(fork.getClasses()).toContain(BLOGPOST);

    // ...but the original's identity does not.
    expect(fork.get(core.properties.parent)).toBe(drive.subject);
  });

  it('merges a fork onto the original without disturbing its identity', async ({
    expect,
  }) => {
    const { store } = await testStore();

    const drive = await store.newResource({
      isA: DRIVE,
      noParent: true,
    });
    await drive.save();

    const original = await store.newResource({
      parent: drive.subject,
      isA: BLOGPOST,
      propVals: {
        [core.properties.name]: 'Cheese',
        [core.properties.description]: 'A post about cheese.',
      },
    });
    await original.save();

    const forksFolder = await store.newResource({
      parent: drive.subject,
      isA: core.classes.class,
    });
    await forksFolder.save();

    const fork = await forkResource(store, original, forksFolder.subject);
    await fork.set(core.properties.name, 'Cheese, Revisited');
    await fork.save();

    // The original is untouched while the fork is being worked on.
    expect(original.get(core.properties.name)).toBe('Cheese');

    const merged = await mergeFork(store, fork);

    expect(merged.subject).toBe(original.subject);
    expect(merged.get(core.properties.name)).toBe('Cheese, Revisited');
    expect(merged.get(core.properties.description)).toBe(
      'A post about cheese.',
    );

    // The merge must not move the original into the forks folder, nor make it
    // claim to be a fork.
    expect(merged.get(core.properties.parent)).toBe(drive.subject);
    expect(merged.getClasses()).toContain(BLOGPOST);
    expect(merged.getClasses()).not.toContain(forks.classes.fork);
    expect(merged.get(forks.properties.originalSubject)).toBe(undefined);
  });

  it('carries a property removed in the fork through the merge', async ({
    expect,
  }) => {
    const { store } = await testStore();

    const drive = await store.newResource({
      isA: DRIVE,
      noParent: true,
    });
    await drive.save();

    const original = await store.newResource({
      parent: drive.subject,
      isA: BLOGPOST,
      propVals: {
        [core.properties.name]: 'Cheese',
        [core.properties.description]: 'Fork me away.',
      },
    });
    await original.save();

    const fork = await forkResource(store, original, drive.subject);
    fork.remove(core.properties.description);
    await fork.save();

    const merged = await mergeFork(store, fork);

    expect(merged.get(core.properties.description)).toBe(undefined);
    expect(merged.get(core.properties.name)).toBe('Cheese');
  });

  it('does not carry the original’s read grant onto the fork', async ({
    expect,
  }) => {
    const { store } = await testStore();

    const drive = await store.newResource({
      isA: DRIVE,
      noParent: true,
    });
    await drive.save();

    // A published page: explicitly readable by the public.
    const published = await store.newResource({
      parent: drive.subject,
      isA: BLOGPOST,
      propVals: {
        [core.properties.name]: 'Cheese',
        [core.properties.read]: [PUBLIC_AGENT],
      },
    });
    await published.save();

    const fork = await forkResource(store, published, drive.subject);

    // If the fork inherited `read: [publicAgent]` it would be public the moment
    // it was created, which is the one thing a fork must never be.
    expect(fork.get(core.properties.read)).toBe(undefined);
    expect(fork.get(core.properties.write)).toBe(undefined);
    expect(fork.get(core.properties.name)).toBe('Cheese');
  });

  it('does not push the fork’s ACL onto the original when merging', async ({
    expect,
  }) => {
    const { store } = await testStore();

    const drive = await store.newResource({
      isA: DRIVE,
      noParent: true,
    });
    await drive.save();

    const original = await store.newResource({
      parent: drive.subject,
      isA: BLOGPOST,
      propVals: {
        [core.properties.name]: 'Cheese',
        [core.properties.read]: [PUBLIC_AGENT],
      },
    });
    await original.save();

    const fork = await forkResource(store, original, drive.subject);
    await fork.set(core.properties.name, 'Cheese Revisited');
    await fork.save();

    const merged = await mergeFork(store, fork);

    expect(merged.get(core.properties.name)).toBe('Cheese Revisited');
    // The original keeps the grant it had; the merge neither strips nor grants.
    expect(merged.get(core.properties.read)).toEqual([PUBLIC_AGENT]);
  });

  it('forks a document body and merges concurrent body edits as a CRDT', async ({
    expect,
  }) => {
    const { store, posted } = await testStore();

    const drive = await store.newResource({ isA: DRIVE, noParent: true });
    await drive.save();

    // A document whose body lives in the Loro `doc` container, not in propvals.
    const original = await store.newResource({
      parent: drive.subject,
      isA: DOCUMENT_V2,
      propVals: { [core.properties.name]: 'Original Doc' },
    });
    original.getLoroDoc()!.getMap('doc').set('intro', 'shared intro');
    original.markDirty();
    await original.save();

    // Fork: the fork's body must be seeded from the original (not empty), and
    // it must record a fork version for the CRDT merge.
    const fork = await forkResource(store, original, drive.subject);
    expect(fork.getLoroDoc()!.getMap('doc').get('intro')).toBe('shared intro');
    expect(fork.get(forks.properties.forkVersion)).toBeTruthy();
    const genesis = posted.find(
      commit => commit.subject === fork.subject && commit.isGenesis,
    )!;
    const firstState = new Resource(fork.subject);
    firstState.setStore(store);
    firstState.importLoroUpdate(genesis.loroUpdate!);
    expect(firstState.getLoroDoc()!.getMap('doc').get('intro')).toBe(
      'shared intro',
    );

    // Concurrent body edits: the fork adds one key, the original another.
    fork.getLoroDoc()!.getMap('doc').set('fromFork', 'DRAFT');
    fork.markDirty();
    await fork.save();

    original.getLoroDoc()!.getMap('doc').set('fromOriginal', 'ORIGINAL');
    original.markDirty();
    await original.save();

    const merged = await mergeFork(store, fork);
    const body = merged.getLoroDoc()!.getMap('doc');

    // Both concurrent body edits survive — a true merge, not an overwrite.
    expect(body.get('fromFork')).toBe('DRAFT');
    expect(body.get('fromOriginal')).toBe('ORIGINAL');
    expect(body.get('intro')).toBe('shared intro');

    // The original keeps its identity.
    expect(merged.get(core.properties.name)).toBe('Original Doc');
    expect(merged.getClasses()).not.toContain(forks.classes.fork);
    expect(merged.get(forks.properties.originalSubject)).toBe(undefined);
    expect(merged.get(forks.properties.forkVersion)).toBe(undefined);
  });

  it('refuses to merge a resource that is not a fork of anything', async ({
    expect,
  }) => {
    const { store } = await testStore();

    const drive = await store.newResource({
      isA: DRIVE,
      noParent: true,
    });
    await drive.save();

    const orphan = await store.newResource({
      parent: drive.subject,
      isA: BLOGPOST,
      propVals: { [core.properties.name]: 'Not a fork' },
    });
    await orphan.save();

    await expect(mergeFork(store, orphan)).rejects.toThrow(
      /not a fork of anything/,
    );
  });

  it('merging a fork does not revert a concurrent edit to an untouched property', async ({
    expect,
  }) => {
    const { store } = await testStore();

    const drive = await store.newResource({ isA: DRIVE, noParent: true });
    await drive.save();

    const original = await store.newResource({
      parent: drive.subject,
      isA: BLOGPOST,
      propVals: {
        [core.properties.name]: 'Cheese',
        [core.properties.description]: 'First version.',
      },
    });
    await original.save();

    // Alice forks and changes only the name.
    const fork = await forkResource(store, original, drive.subject);
    await fork.set(core.properties.name, 'Cheese, Revisited');
    await fork.save();

    // Bob concurrently rewrites the description on the original.
    await original.set(core.properties.description, 'Bob rewrote this.');
    await original.save();

    const merged = await mergeFork(store, fork);

    expect(merged.get(core.properties.name)).toBe('Cheese, Revisited');
    // The property the fork never touched keeps Bob's concurrent edit.
    expect(merged.get(core.properties.description)).toBe('Bob rewrote this.');
  });

  it('reports a conflict when both sides changed the same property, and can refuse to merge', async ({
    expect,
  }) => {
    const { store } = await testStore();

    const drive = await store.newResource({ isA: DRIVE, noParent: true });
    await drive.save();

    const original = await store.newResource({
      parent: drive.subject,
      isA: BLOGPOST,
      propVals: { [core.properties.name]: 'Cheese' },
    });
    await original.save();

    const fork = await forkResource(store, original, drive.subject);
    await fork.set(core.properties.name, 'Alice’s name');
    await fork.save();

    await original.set(core.properties.name, 'Bob’s name');
    await original.save();

    const changes = diffFork(fork, original);
    const nameChange = changes.find(c => c.property === core.properties.name);
    expect(nameChange?.conflict).toBe(true);

    await expect(
      mergeFork(store, fork, { onConflict: 'throw' }),
    ).rejects.toThrow(/changed on both/);

    // Nothing was written: the original still holds Bob's value.
    expect(original.get(core.properties.name)).toBe('Bob’s name');

    // Default resolution lets the fork win.
    const merged = await mergeFork(store, fork);
    expect(merged.get(core.properties.name)).toBe('Alice’s name');
  });

  it('a property untouched by the fork is not reported as a change', async ({
    expect,
  }) => {
    const { store } = await testStore();

    const drive = await store.newResource({ isA: DRIVE, noParent: true });
    await drive.save();

    const original = await store.newResource({
      parent: drive.subject,
      isA: BLOGPOST,
      propVals: {
        [core.properties.name]: 'Cheese',
        [core.properties.description]: 'Untouched.',
      },
    });
    await original.save();

    const fork = await forkResource(store, original, drive.subject);
    await fork.set(core.properties.name, 'Renamed');
    await fork.save();

    const changes = diffFork(fork, original);
    expect(changes.map(c => c.property)).toEqual([core.properties.name]);
  });
});
