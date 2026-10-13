import { describe, expect, it, vi } from 'vitest';
import { Store } from './store.js';
import { CollectionBuilder } from './collectionBuilder.js';
import { Resource } from './resource.js';
import { core } from './ontologies/core.js';
import { notifications } from './ontologies/notifications.js';
import type { ClientDbWorker } from './client-db.js';

const DRIVE = 'atomic:personal';
const OTHER = 'atomic:other-person';
const DRIVE_PROP = 'https://atomicdata.dev/properties/drive';
const json = (subject: string, drive: string) =>
  JSON.stringify({
    '@id': subject,
    [core.properties.isA]: [notifications.classes.notification],
    [DRIVE_PROP]: drive,
  });

describe('explicit drive scope on local collections', () => {
  it('does not return another account’s notifications from the local index', async () => {
    const store = new Store({
      serverUrl: 'https://example.com',
      connect: false,
    });
    store.setDrive(DRIVE);
    store.finishDriveSync(DRIVE, 1, Date.now());
    const query = vi.fn(async (opts: { drive?: string }) => {
      const subjects =
        opts.drive === DRIVE
          ? ['atomic:mine']
          : ['atomic:mine', 'atomic:theirs'];

      return {
        subjects,
        count: subjects.length,
        resources: subjects.map(s =>
          json(s, s === 'atomic:mine' ? DRIVE : OTHER),
        ),
      };
    });
    store.setClientDb({ isReady: true, query } as unknown as ClientDbWorker);
    const collection = await new CollectionBuilder(store)
      .setProperty(core.properties.isA)
      .setValue(notifications.classes.notification)
      .setDrive(DRIVE)
      .buildAndFetch();
    expect(await collection.getAllMembers()).toEqual(['atomic:mine']);
    expect(query).toHaveBeenCalledWith(
      expect.objectContaining({ drive: DRIVE }),
    );
  });

  it('does not optimistically admit a notification pushed from another drive', async () => {
    const store = new Store({
      serverUrl: 'https://example.com',
      connect: false,
    });
    store.setDrive(DRIVE);
    store.finishDriveSync(DRIVE, 1, Date.now());
    store.setClientDb({
      isReady: true,
      query: async () => ({ subjects: [], count: 0 }),
    } as unknown as ClientDbWorker);
    const collection = await new CollectionBuilder(store)
      .setProperty(core.properties.isA)
      .setValue(notifications.classes.notification)
      .setDrive(DRIVE)
      .buildAndFetch();
    const foreign = new Resource('atomic:theirs');
    await foreign.set(
      core.properties.isA,
      [notifications.classes.notification],
      false,
    );
    await foreign.set(DRIVE_PROP, OTHER, false);
    expect(collection.applyResourceChange(foreign.subject, foreign)).toBe(
      'unchanged',
    );
    expect(collection.totalMembers).toBe(0);
  });
});
