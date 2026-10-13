import { describe, expect, it, vi } from 'vitest';
import { AtomicError, ErrorType, type Store } from '@tomic/lib';
import { deviceHasDriveData, driveHasServer } from './driveData';
import { isOriginWithoutNode } from './originNode';

vi.mock('./originNode', () => ({ isOriginWithoutNode: vi.fn() }));

describe('refreshing drive availability', () => {
  it('rechecks an earlier failure after data arrives instead of retaining the miss', async () => {
    vi.mocked(isOriginWithoutNode).mockReturnValue(true);
    let error: Error | undefined = new Error('Not found');
    const store = {
      getServerUrl: () => 'https://app.example',
      isLocalOnlyDrive: () => true,
      getResource: vi.fn(async () => ({ error })),
      getResourceLoading: () => ({ error }),
      reloadResource: vi.fn(async () => {
        error = undefined;
      }),
    };
    const typedStore = store as unknown as Store;
    expect(await deviceHasDriveData(typedStore, 'did:ad:drive')).toBe(false);
    expect(
      await deviceHasDriveData(typedStore, 'did:ad:drive', { refresh: true }),
    ).toBe(true);
  });

  it('does not report an errored resource as available just because the read resolved', async () => {
    const store = {
      getResource: vi
        .fn()
        .mockResolvedValue({ error: new Error('Unauthorized') }),
    };
    expect(
      await deviceHasDriveData(store as unknown as Store, 'did:ad:drive'),
    ).toBe(false);
  });

  it('asks again as the signed-in agent when the cached answer was a public 401', async () => {
    const unauthorized = new AtomicError(
      'Unauthorized.',
      ErrorType.Unauthorized,
    );
    const store = {
      getAgent: () => ({ subject: 'did:ad:agent:me' }),
      getResource: vi.fn().mockResolvedValue({ error: unauthorized }),
      fetchResourceFromServer: vi.fn().mockResolvedValue({ error: undefined }),
    };

    expect(
      await deviceHasDriveData(store as unknown as Store, 'did:ad:drive'),
    ).toBe(true);
    expect(store.fetchResourceFromServer).toHaveBeenCalledWith('did:ad:drive');
  });

  it('does not report availability when local storage rejects the read', async () => {
    const store = {
      getResource: vi.fn().mockRejectedValue(new Error('Storage unavailable')),
    };
    expect(
      await deviceHasDriveData(store as unknown as Store, 'did:ad:drive'),
    ).toBe(false);
  });
  it.each([
    [true, false, true],
    [false, true, true],
    [false, false, false],
  ])(
    'nodeless=%s localOnly=%s reloadsLocal=%s',
    async (nodeless, localOnly, local) => {
      vi.mocked(isOriginWithoutNode).mockReturnValue(nodeless);
      const store = {
        getServerUrl: () => 'https://app.example',
        isLocalOnlyDrive: () => localOnly,
        reloadResource: vi.fn().mockResolvedValue(undefined),
        fetchResourceFromServer: vi.fn().mockResolvedValue(undefined),
        getResourceLoading: () => ({ error: undefined }),
      };
      expect(
        await deviceHasDriveData(store as unknown as Store, 'did:ad:drive', {
          refresh: true,
        }),
      ).toBe(true);
      expect(store.reloadResource).toHaveBeenCalledTimes(local ? 1 : 0);
      expect(store.fetchResourceFromServer).toHaveBeenCalledTimes(
        local ? 0 : 1,
      );
    },
  );
});

describe('driveHasServer', () => {
  it.each([
    [false, false, true],
    [true, false, false],
    [false, true, false],
    [true, true, false],
  ])('nodeless=%s localOnly=%s hasServer=%s', (nodeless, localOnly, has) => {
    vi.mocked(isOriginWithoutNode).mockReturnValue(nodeless);
    const store = {
      getServerUrl: () => 'https://app.example',
      isLocalOnlyDrive: () => localOnly,
    };
    expect(driveHasServer(store, 'did:ad:drive')).toBe(has);
  });
});
