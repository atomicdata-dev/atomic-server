import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Store } from '@tomic/react';
import { adoptDriveFromDeepLink } from './adoptDriveFromDeepLink';
import { isOriginWithoutNode } from './originNode';

vi.mock('./originNode', () => ({ isOriginWithoutNode: vi.fn() }));
vi.mock('@tomic/react', () => ({
  enableLoro: vi.fn().mockResolvedValue(undefined),
  isUnauthorized: vi.fn().mockReturnValue(false),
  server: { classes: { drive: 'Drive' } },
}));

afterEach(() => vi.unstubAllGlobals());

describe('deep links before sign-in', () => {
  function setup(nodeless: boolean) {
    vi.mocked(isOriginWithoutNode).mockReturnValue(nodeless);
    vi.stubGlobal('window', { location: { search: '?subject=did:ad:drive' } });

    return {
      getAgent: vi.fn().mockReturnValue(undefined),
      getServerUrl: vi.fn().mockReturnValue('https://app.example'),
      getDrive: vi.fn().mockReturnValue(undefined),
      serverConnected: true,
      getResource: vi.fn().mockResolvedValue({
        get: () => undefined,
        getClasses: () => ['Drive'],
      }),
      setDrive: vi.fn(),
    };
  }

  it('leaves private local links to sign-in without fetching the static host', async () => {
    const store = setup(true);
    await adoptDriveFromDeepLink(store as unknown as Store);
    expect(store.getResource).not.toHaveBeenCalled();
    expect(store.setDrive).not.toHaveBeenCalled();
  });

  it('still resolves public links on an actual node for anonymous users', async () => {
    const store = setup(false);
    await adoptDriveFromDeepLink(store as unknown as Store);
    expect(store.getResource).toHaveBeenCalledWith('did:ad:drive');
    expect(store.setDrive).toHaveBeenCalledWith('did:ad:drive');
  });
});
