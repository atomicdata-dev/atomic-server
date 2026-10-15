import { describe, expect, it, vi } from 'vitest';
import {
  AtomicError,
  core,
  dataBrowser,
  ErrorType,
  Store as RealStore,
  NOT_AVAILABLE_LOCALLY_MESSAGE,
  type Resource,
  type Store,
} from '@tomic/react';
import {
  isUnavailableResource,
  unavailableReason,
  withoutUnavailable,
} from './unavailableResources';

const DRIVE = 'did:ad:drive:one';
const TRASH = 'did:ad:folder:trash';

type Fake = { props?: Record<string, unknown>; error?: Error };

const setup = (
  resources: Record<string, Fake>,
  destroyed: string[] = [],
  trash: string | null = TRASH,
) => {
  const all: Record<string, Fake> = {
    [DRIVE]: { props: { [dataBrowser.properties.trashFolder]: trash } },
    ...resources,
  };
  const toResource = (subject: string) =>
    ({
      subject,
      error: all[subject]?.error,
      get: (prop: string) => all[subject]?.props?.[prop],
    }) as unknown as Resource;
  const lookup = vi.fn(toResource);
  const store = {
    isTrashed: RealStore.prototype.isTrashed,
    peekTrashFolder: RealStore.prototype.peekTrashFolder,
    isDestroyed: (subject: string) => destroyed.includes(subject),
    // The drive is read from what is already loaded, never fetched.
    resources: new Map([[DRIVE, toResource(DRIVE)]]),
    normalizeSubject: (subject: string) => subject,
    getResourceLoading: lookup,
  } as unknown as Store;

  return { store, resource: toResource, lookup };
};

describe('isUnavailableResource', () => {
  it('keeps a normal resource', () => {
    const { store, resource } = setup({
      a: { props: { [core.properties.parent]: DRIVE } },
    });

    expect(isUnavailableResource(store, DRIVE, resource('a'))).toBe(false);
  });

  it('hides a destroyed resource', () => {
    const { store, resource } = setup({ a: {} }, ['a']);

    expect(isUnavailableResource(store, DRIVE, resource('a'))).toBe(true);
  });

  it('hides a resource in the trash, or under a trashed folder', () => {
    const { store, resource } = setup({
      a: { props: { [core.properties.parent]: TRASH } },
      folder: { props: { [core.properties.parent]: TRASH } },
      b: { props: { [core.properties.parent]: 'folder' } },
    });

    expect(isUnavailableResource(store, DRIVE, resource('a'))).toBe(true);
    expect(isUnavailableResource(store, DRIVE, resource('b'))).toBe(true);
  });

  it('keeps everything when the drive has no trash folder', () => {
    const { store, resource } = setup(
      { a: { props: { [core.properties.parent]: TRASH } } },
      [],
      null,
    );

    expect(isUnavailableResource(store, DRIVE, resource('a'))).toBe(false);
  });

  it('hides resources that are gone or uncached, but not ones that failed', () => {
    const { store, resource } = setup({
      missing: { error: new AtomicError('nope', ErrorType.NotFound) },
      offline: {
        error: new AtomicError(
          NOT_AVAILABLE_LOCALLY_MESSAGE,
          ErrorType.Transport,
        ),
      },
      broken: { error: new AtomicError('boom', ErrorType.Server) },
    });

    expect(isUnavailableResource(store, DRIVE, resource('missing'))).toBe(true);
    expect(isUnavailableResource(store, DRIVE, resource('offline'))).toBe(true);
    expect(isUnavailableResource(store, DRIVE, resource('broken'))).toBe(false);
    expect(unavailableReason(store, DRIVE, resource('missing'))).toBe('gone');
    expect(unavailableReason(store, DRIVE, resource('offline'))).toBe(
      'uncached',
    );
    expect(unavailableReason(store, DRIVE, resource('broken'))).toBeUndefined();
  });

  it('stops on a parent cycle by visiting each node once', () => {
    const { store, resource, lookup } = setup({
      a: { props: { [core.properties.parent]: 'b' } },
      b: { props: { [core.properties.parent]: 'c' } },
      c: { props: { [core.properties.parent]: 'a' } },
    });

    lookup.mockClear();

    expect(isUnavailableResource(store, DRIVE, resource('a'))).toBe(false);
    // b and c once each; reaching a again ends the walk. The drive is peeked.
    expect(lookup).toHaveBeenCalledTimes(2);
  });
});

describe('withoutUnavailable', () => {
  it('filters subjects, keeping order and unknown ones', () => {
    const { store, resource } = setup({
      a: { props: { [core.properties.parent]: TRASH } },
      b: {},
    });
    const resources = new Map([
      ['a', resource('a')],
      ['b', resource('b')],
    ]);

    expect(
      withoutUnavailable(store, DRIVE, ['a', 'b', 'c'], resources),
    ).toEqual({ available: ['b', 'c'], gone: ['a'] });
  });

  it('hides uncached subjects without reporting them as gone', () => {
    const { store, resource } = setup({
      off: {
        error: new AtomicError(
          NOT_AVAILABLE_LOCALLY_MESSAGE,
          ErrorType.Transport,
        ),
      },
    });
    const resources = new Map([['off', resource('off')]]);

    expect(withoutUnavailable(store, DRIVE, ['off'], resources)).toEqual({
      available: [],
      gone: [],
    });
  });
});
