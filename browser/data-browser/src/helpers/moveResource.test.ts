import { describe, expect, it } from 'vitest';
import { core, server } from '@tomic/react';
import {
  copyResourceTree,
  moveBlockedReason,
  replaceWithRedirect,
  trashDescendants,
} from './moveResource';

// drive <- a <- b <- c ; drive <- d ; other (separate drive)
const parents: Record<string, string> = {
  a: 'drive',
  b: 'a',
  c: 'b',
  d: 'drive',
  'other-child': 'other',
};
const root = (s: string): string => (parents[s] ? root(parents[s]) : s);
const store = {
  getResourceLoading: (s: string) => ({
    get: (p: string) => (p === core.properties.parent ? parents[s] : undefined),
  }),
  driveOfSubject: root,
} as unknown as Parameters<typeof moveBlockedReason>[0];

describe('moveBlockedReason', () => {
  it('allows moving to a sibling branch', () => {
    expect(moveBlockedReason(store, 'c', 'd')).toBeUndefined();
    expect(moveBlockedReason(store, 'b', 'drive')).toBeUndefined();
  });

  it('refuses itself and descendants', () => {
    expect(moveBlockedReason(store, 'a', 'a')).toMatch(/into itself/);
    expect(moveBlockedReason(store, 'a', 'c')).toMatch(/inside it/);
  });

  it('allows another drive (a copy-move)', () => {
    expect(moveBlockedReason(store, 'a', 'other')).toBeUndefined();
  });

  it('refuses content-addressed properties', () => {
    expect(moveBlockedReason(store, 'did:ad:prop:abc', 'd')).toMatch(
      /property/,
    );
  });
});

/** Minimal stand-ins for Store/Resource: enough to see what gets written. */
function fakeResource(subject: string, props: Record<string, unknown>) {
  const saved: Record<string, unknown>[] = [];

  return {
    subject,
    props,
    saved,
    getClasses: () => (props[core.properties.isA] as string[]) ?? [],
    getPropVals: () => ({ ...props }),
    hasLoroBody: () => false,
    set: async (p: string, v: unknown) => void (props[p] = v),
    remove: (p: string) => void delete props[p],
    save: async () => void saved.push({ ...props }),
  };
}

describe('copyResourceTree', () => {
  const folder = fakeResource('old:folder', {
    [core.properties.isA]: ['Folder'],
    [core.properties.name]: 'F',
    [core.properties.parent]: 'old:drive',
    [core.properties.write]: ['agent'],
  });
  const child = fakeResource('old:child', {
    [core.properties.isA]: ['Doc'],
    [core.properties.parent]: 'old:folder',
    related: ['old:folder', 'elsewhere'],
    link: 'old:folder',
  });
  const old = { 'old:folder': folder, 'old:child': child } as Record<
    string,
    ReturnType<typeof fakeResource>
  >;
  const members: Record<string, string[]> = { 'old:folder': ['old:child'] };
  const created: ReturnType<typeof fakeResource>[] = [];
  const fakeStore = {
    getResource: async (s: string) =>
      Object.assign(old[s], {
        getChildrenCollection: async () => ({
          getAllMembers: async () => members[s] ?? [],
        }),
      }),
    newResource: async ({ parent, isA }: { parent: string; isA: string[] }) => {
      const r = fakeResource(`new:${created.length}`, {
        [core.properties.isA]: isA,
        [core.properties.parent]: parent,
      });
      created.push(r);

      return r;
    },
  } as unknown as Parameters<typeof copyResourceTree>[0];

  it('copies the tree under the target with new ids and rewritten references', async () => {
    const copied = await copyResourceTree(
      fakeStore,
      'old:folder',
      'other:drive',
    );

    expect(copied).toBe('new:0');
    expect(created[0].props).toMatchObject({
      [core.properties.parent]: 'other:drive',
      [core.properties.name]: 'F',
    });
    // Rights are not carried over: they follow the new parent.
    expect(created[0].props[core.properties.write]).toBeUndefined();
    expect(created[1].props).toMatchObject({
      [core.properties.parent]: 'new:0',
      related: ['new:0', 'elsewhere'],
      link: 'new:0',
    });
    expect(created.every(c => c.saved.length === 1)).toBe(true);
  });

  it('replaces the original with a Redirect, keeping parent and rights', async () => {
    await replaceWithRedirect(folder as never, 'new:0');

    expect(folder.props).toEqual({
      [core.properties.isA]: [server.classes.redirect],
      [server.properties.destination]: 'new:0',
      [core.properties.parent]: 'old:drive',
      [core.properties.write]: ['agent'],
      [core.properties.name]: 'F',
    });
  });

  it('trashes the direct children of the Redirect, and only those', async () => {
    const trashed: string[][] = [];
    const trashStore = {
      driveOfSubject: () => 'old:drive',
      getResource: async () => ({
        getChildrenCollection: async () => ({
          getAllMembers: async () => ['old:child', 'old:child2'],
        }),
      }),
      trash: async (s: string, d: string) => {
        trashed.push([s, d]);

        return true;
      },
    } as unknown as Parameters<typeof trashDescendants>[0];

    await trashDescendants(trashStore, 'old:folder');

    expect(trashed).toEqual([
      ['old:child', 'old:drive'],
      ['old:child2', 'old:drive'],
    ]);
  });
});
