import { describe, expect, it } from 'vitest';
import {
  AtomicError,
  core,
  dataBrowser,
  ErrorType,
  NOT_AVAILABLE_LOCALLY_MESSAGE,
  type Resource,
  type Store,
} from '@tomic/react';
import {
  isUnavailableResource,
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
  const store = {
    isDestroyed: (subject: string) => destroyed.includes(subject),
    getResourceLoading: toResource,
  } as unknown as Store;

  return { store, resource: toResource };
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

  it('hides resources that are gone, but not ones that merely failed', () => {
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
  });

  it('terminates on a parent cycle', () => {
    const { store, resource } = setup({
      a: { props: { [core.properties.parent]: 'b' } },
      b: { props: { [core.properties.parent]: 'a' } },
    });

    expect(isUnavailableResource(store, DRIVE, resource('a'))).toBe(false);
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
    ).toEqual(['b', 'c']);
  });
});
