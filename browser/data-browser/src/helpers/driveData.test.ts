import { describe, expect, it, vi } from 'vitest';
import type { Store } from '@tomic/lib';
import { deviceHasDriveData } from './driveData';
import { isOriginWithoutNode } from './originNode';

vi.mock('./originNode', () => ({ isOriginWithoutNode: vi.fn() }));

describe('refreshing drive availability', () => {
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
