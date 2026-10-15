import { describe, expect, it } from 'vitest';
import { Store } from './store.js';
import { core } from './ontologies/core.js';
import { dataBrowser } from './ontologies/dataBrowser.js';
import type { Resource } from './resource.js';

const DRIVE = 'did:ad:drive';
const TRASH = 'did:ad:trash';

type Fake = Record<string, unknown>;

/** A store whose resources are plain in-memory fakes; nothing is fetched. */
const setup = (nodes: Record<string, Fake>, destroyed: string[] = []) => {
  const store = new Store();
  const saved: string[] = [];
  const all: Record<string, Fake> = { [DRIVE]: {}, ...nodes };

  const make = (subject: string) => {
    const props = (all[subject] ??= {});
    const res = {
      subject,
      error: props.__error as Error | undefined,
      get: (p: string) => props[p],
      set: async (p: string, v: unknown) => {
        props[p] = v;
      },
      remove: (p: string) => {
        delete props[p];
      },
      save: async () => {
        saved.push(subject);
      },
    };

    return res as unknown as Resource;
  };

  store.resources.set(DRIVE, make(DRIVE));
  store.getResourceLoading = ((s: string) => make(s)) as never;
  store.getResource = (async (s: string) => make(s)) as never;
  store.isDestroyed = (s: string) => destroyed.includes(s);

  return { store, all, saved, make };
};

const withTrash = (all: Fake) => {
  all[dataBrowser.properties.trashFolder] = TRASH;
};

describe('Store.isTrashed', () => {
  it('is false without a known Trash folder', () => {
    const { store, make } = setup({ a: { [core.properties.parent]: TRASH } });

    expect(store.isTrashed(make('a'), DRIVE)).toBe(false);
  });

  it('checks the direct parent by default and accepts a subject', () => {
    const { store, all, make } = setup({
      a: { [core.properties.parent]: TRASH },
      b: { [core.properties.parent]: 'folder' },
      folder: { [core.properties.parent]: TRASH },
    });
    withTrash(all[DRIVE]);

    expect(store.isTrashed(make('a'), DRIVE)).toBe(true);
    expect(store.isTrashed('a', DRIVE)).toBe(true);
    expect(store.isTrashed(make('b'), DRIVE)).toBe(false);
  });

  it('walks loaded ancestors when deep, and survives parent cycles', () => {
    const { store, all, make } = setup({
      b: { [core.properties.parent]: 'folder' },
      folder: { [core.properties.parent]: TRASH },
      x: { [core.properties.parent]: 'y' },
      y: { [core.properties.parent]: 'x' },
    });
    withTrash(all[DRIVE]);

    expect(store.isTrashed(make('b'), DRIVE, { deep: true })).toBe(true);
    expect(store.isTrashed(make('x'), DRIVE, { deep: true })).toBe(false);
  });
});

describe('Store.trash', () => {
  it('refuses a content-addressed property', async () => {
    const { store } = setup({});

    await expect(
      store.trash('atomic:prop:' + 'a'.repeat(64), DRIVE),
    ).rejects.toThrow("A property can't be moved to the trash.");
  });

  it('reparents into the Trash and remembers the old parent', async () => {
    const { store, all, saved } = setup({
      a: { [core.properties.parent]: 'folder' },
      [TRASH]: {},
    });
    withTrash(all[DRIVE]);

    expect(await store.trash('a', DRIVE)).toBe(true);
    expect(all.a[core.properties.parent]).toBe(TRASH);
    expect(all.a[dataBrowser.properties.trashedFrom]).toBe('folder');
    expect(saved).toContain('a');
  });

  it('does nothing for an item already in the Trash or the Trash itself', async () => {
    const { store, all, saved } = setup({
      a: { [core.properties.parent]: TRASH },
      [TRASH]: {},
    });
    withTrash(all[DRIVE]);

    expect(await store.trash('a', DRIVE)).toBe(false);
    expect(await store.trash(TRASH, DRIVE)).toBe(false);
    expect(saved).toEqual([]);
  });
});

describe('Store.restore', () => {
  it('moves back to the old parent and clears trashedFrom', async () => {
    const { store, all } = setup({
      a: {
        [core.properties.parent]: TRASH,
        [dataBrowser.properties.trashedFrom]: 'folder',
      },
      folder: {},
    });

    await store.restore('a', DRIVE);

    expect(all.a[core.properties.parent]).toBe('folder');
    expect(dataBrowser.properties.trashedFrom in all.a).toBe(false);
  });

  it('falls back to the drive when the old parent is destroyed or unreadable', async () => {
    for (const [destroyed, error] of [
      [['folder'], undefined],
      [[], new Error('gone')],
    ] as const) {
      const { store, all } = setup(
        {
          a: {
            [core.properties.parent]: TRASH,
            [dataBrowser.properties.trashedFrom]: 'folder',
          },
          folder: { __error: error },
        },
        [...destroyed],
      );

      await store.restore('a', DRIVE);

      expect(all.a[core.properties.parent]).toBe(DRIVE);
    }
  });
});

describe('Store.peekTrashFolder', () => {
  it('reads only what is loaded', () => {
    const { store, all } = setup({});

    expect(store.peekTrashFolder(DRIVE)).toBeUndefined();
    expect(store.peekTrashFolder(undefined)).toBeUndefined();
    withTrash(all[DRIVE]);
    expect(store.peekTrashFolder(DRIVE)).toBe(TRASH);
  });
});
