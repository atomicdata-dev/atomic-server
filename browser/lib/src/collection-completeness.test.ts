import { describe, expect, it, vi } from 'vitest';
import {
  Store,
  CollectionBuilder,
  core,
  collections,
  type ClientDbWorker,
  type Agent,
} from './index.js';

const drive = 'atomic:drive';

function setup(subjects?: string[]) {
  const store = new Store({ serverUrl: 'https://example.com', connect: false });
  store.setDrive(drive);
  vi.spyOn(store, 'waitForServerConnected').mockResolvedValue(false);
  if (subjects)
    store.setClientDb({
      isReady: true,
      query: async () => ({ subjects, count: subjects.length }),
    } as unknown as ClientDbWorker);
  const build = () =>
    new CollectionBuilder(store)
      .setProperty(core.properties.parent)
      .setValue(drive)
      .setDrive(drive)
      .buildAndFetch();

  return { store, build };
}

describe('complete collection reads', () => {
  it('does not mistake an unavailable index for an empty result', async () => {
    const { build } = setup();
    const collection = await build();
    expect(await collection.getAllMembers()).toEqual([]);
    await expect(
      collection.getAllMembers({ requireComplete: true }),
    ).rejects.toThrow('incomplete');
  });

  it('keeps partial cached rows readable without certifying their completeness', async () => {
    const { build } = setup(['atomic:cached']);
    const collection = await build();
    expect(await collection.getAllMembers()).toEqual(['atomic:cached']);
    await expect(
      collection.getAllMembers({ requireComplete: true }),
    ).rejects.toThrow('incomplete');
  });

  it('accepts a scoped empty result only after that drive reconciled', async () => {
    const { store, build } = setup([]);
    store.finishDriveSync(drive, 0, Date.now());
    const collection = await build();
    expect(await collection.getAllMembers({ requireComplete: true })).toEqual(
      [],
    );
    store.setAgent({ subject: 'atomic:agent:other' } as Agent);
    await expect(
      collection.getAllMembers({ requireComplete: true }),
    ).rejects.toThrow('incomplete');
  });

  it('does not certify an unscoped index from one reconciled drive', async () => {
    const { store } = setup([]);
    store.finishDriveSync(drive, 0, Date.now());
    const collection = await new CollectionBuilder(store)
      .setProperty(core.properties.isA)
      .setValue('https://example.com/Class')
      .buildAndFetch();
    await expect(
      collection.getAllMembers({ requireComplete: true }),
    ).rejects.toThrow('incomplete');
  });

  it('refreshes a partial cache from the authority when completeness is required', async () => {
    const { store, build } = setup(['atomic:cached']);
    const collection = await build();
    store.injectFetch(
      async input =>
        new Response(
          JSON.stringify({
            '@id': String(input),
            [collections.properties.members]: [
              'atomic:cached',
              'atomic:remote',
            ],
            [collections.properties.totalMembers]: 2,
          }),
          { status: 200 },
        ),
    );
    store.setServerConnected(true);
    expect(await collection.getAllMembers({ requireComplete: true })).toEqual([
      'atomic:cached',
      'atomic:remote',
    ]);
    expect(collection.completeness).toBe('complete');
  });

  it('invalidates completeness when placement changes away and back', async () => {
    const { store, build } = setup([]);
    store.setDriveServer(drive, 'https://example.com');
    store.finishDriveSync(drive, 0, Date.now());
    const collection = await build();
    expect(collection.completeness).toBe('complete');
    store.setDriveServer(drive, 'https://other.example.com');
    store.setDriveServer(drive, 'https://example.com');
    expect(collection.completeness).toBe('partial');
  });

  it('invalidates completeness when the database is replaced', async () => {
    const { store, build } = setup([]);
    store.finishDriveSync(drive, 0, Date.now());
    const collection = await build();
    store.setClientDb(undefined);
    await expect(
      collection.getAllMembers({ requireComplete: true }),
    ).rejects.toThrow('incomplete');
  });
});
