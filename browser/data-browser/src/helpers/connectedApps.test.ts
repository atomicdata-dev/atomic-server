import type { Store } from '@tomic/react';
import { describe, expect, it } from 'vitest';
import { rememberConnectedApp } from './connectedApps';

const storeFailingWith = (message: string) =>
  ({
    getResource: async () => ({
      push: () => {},
      save: async () => {
        throw new Error(message);
      },
    }),
  }) as unknown as Store;

describe('rememberConnectedApp', () => {
  it('carries on when the home drive is not enrolled for sync', async () => {
    const store = storeFailingWith(
      'Drive atomic:abc is not enrolled for sync on this node.',
    );

    await expect(rememberConnectedApp(store, 'home', 'agent')).resolves.toBe(
      undefined,
    );
  });

  it('still fails on any other error', async () => {
    await expect(
      rememberConnectedApp(storeFailingWith('Network down'), 'home', 'agent'),
    ).rejects.toThrow('Network down');
  });
});
