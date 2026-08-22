import { describe, expect, it } from 'vitest';
import { core } from '@tomic/react';
import type { Store } from '@tomic/react';
import { handleRequest, isHostRequest, isWithinApp } from './hostStore';

const APP = 'did:ad:app';

/** A store with a parent chain, which is what the write rule is about. */
function fakeStore(parents: Record<string, string | undefined> = {}) {
  const saved: Array<{ subject: string; props: Record<string, unknown> }> = [];
  const destroyed: string[] = [];
  let minted = 0;

  const resource = (subject: string) => ({
    subject,
    error: undefined,
    get: (property: string) =>
      property === core.properties.parent ? parents[subject] : undefined,
    getPropVals: () => ({ [core.properties.parent]: parents[subject] }),
    set: async (property: string, value: unknown) => {
      const entry = saved.find(s => s.subject === subject) ?? {
        subject,
        props: {},
      };
      entry.props[property] = value;

      if (!saved.includes(entry)) saved.push(entry);
    },
    save: async () => undefined,
    destroy: async () => {
      destroyed.push(subject);
    },
  });

  const store = {
    getResource: async (subject: string) => resource(subject),
    newResource: async ({ parent }: { parent: string }) => {
      const subject = `did:ad:new-${++minted}`;
      parents[subject] = parent;

      return resource(subject);
    },
    search: async () => ['did:ad:found'],
  } as unknown as Store;

  return { store, saved, destroyed, parents };
}

const req = (op: string, extra: Record<string, unknown> = {}) =>
  ({ __atomic: true as const, id: 1, op, ...extra }) as never;

describe('what an app may reach', () => {
  it('writes its own data without asking', async () => {
    const { store, saved } = fakeStore({ 'did:ad:mine': APP });

    await handleRequest(
      store,
      APP,
      req('save', { subject: 'did:ad:mine', propVals: { p: 'v' } }),
    );

    expect(saved).toHaveLength(1);
  });

  it('reaches data nested deeper inside itself', async () => {
    const { store } = fakeStore({
      'did:ad:deep': 'did:ad:mid',
      'did:ad:mid': APP,
    });

    await expect(isWithinApp(store, 'did:ad:deep', APP)).resolves.toBe(true);
  });

  it('refuses to write outside itself', async () => {
    const { store, saved } = fakeStore({ 'did:ad:elsewhere': 'did:ad:drive' });

    await expect(
      handleRequest(
        store,
        APP,
        req('save', { subject: 'did:ad:elsewhere', propVals: { p: 'v' } }),
      ),
    ).rejects.toThrow(/only write its own data/);
    expect(saved).toHaveLength(0);
  });

  it('refuses to destroy outside itself', async () => {
    const { store, destroyed } = fakeStore({
      'did:ad:elsewhere': 'did:ad:drive',
    });

    await expect(
      handleRequest(store, APP, req('destroy', { subject: 'did:ad:elsewhere' })),
    ).rejects.toThrow(/only write its own data/);
    expect(destroyed).toHaveLength(0);
  });

  it('refuses to create outside itself', async () => {
    const { store } = fakeStore({ 'did:ad:elsewhere': 'did:ad:drive' });

    await expect(
      handleRequest(store, APP, req('create', { parent: 'did:ad:elsewhere' })),
    ).rejects.toThrow(/only write its own data/);
  });

  it('creates under itself when given no parent', async () => {
    const { store, parents } = fakeStore();

    const created = (await handleRequest(store, APP, req('create'))) as {
      subject: string;
    };

    expect(parents[created.subject]).toBe(APP);
  });

  it('does not loop forever on a parent cycle', async () => {
    const { store } = fakeStore({ a: 'b', b: 'a' });

    await expect(isWithinApp(store, 'a', APP)).resolves.toBe(false);
  });

  it('reads are not restricted to the app', async () => {
    const { store } = fakeStore({ 'did:ad:elsewhere': 'did:ad:drive' });

    // Reads go through the page's own store, so they are already bounded by
    // what the signed-in person may see. Narrowing them further here would
    // make an app unable to show data it was pointed at.
    await expect(
      handleRequest(store, APP, req('get', { subject: 'did:ad:elsewhere' })),
    ).resolves.toMatchObject({ subject: 'did:ad:elsewhere' });
  });

  it('refuses an operation it does not implement', async () => {
    const { store } = fakeStore();

    await expect(handleRequest(store, APP, req('sudo'))).rejects.toThrow(
      /does not do/,
    );
  });
});

describe('isHostRequest', () => {
  it('ignores messages that are not ours', () => {
    expect(isHostRequest({ type: '__atomic_plugin_ready' })).toBe(false);
    expect(isHostRequest(null)).toBe(false);
    expect(isHostRequest({ __atomic: true })).toBe(false);
    expect(isHostRequest({ __atomic: true, id: 1 })).toBe(true);
  });
});
