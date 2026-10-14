import { describe, it } from 'vitest';
import { testStore } from './test-store.js';

describe('Store.hasServerEndpoint', () => {
  it('is false without a drive', async ({ expect }) => {
    const { store } = await testStore();

    expect(store.hasServerEndpoint()).toBe(false);
    expect(store.hasServerEndpoint(undefined)).toBe(false);
  });

  it('is true for a regular drive on a connected server', async ({
    expect,
  }) => {
    const { store } = await testStore();
    const drive = 'did:ad:regular-drive';

    store.setDrive(drive);

    expect(store.hasServerEndpoint()).toBe(true);
    expect(store.hasServerEndpoint(drive)).toBe(true);
  });

  it('is false for a local-only drive', async ({ expect }) => {
    const { store } = await testStore();
    const drive = 'did:ad:local-drive';

    store.registerLocalOnlyDrive(drive);

    expect(store.hasServerEndpoint(drive)).toBe(false);
    expect(store.hasServerEndpoint('did:ad:other-drive')).toBe(true);
  });

  it('is false when the server URL was set with connect: false', async ({
    expect,
  }) => {
    const { store } = await testStore();
    const drive = 'did:ad:regular-drive';

    store.setServerUrl('https://static.example', { connect: false });
    expect(store.hasServerEndpoint(drive)).toBe(false);

    store.setServerUrl('https://node.example');
    expect(store.hasServerEndpoint(drive)).toBe(true);
  });
});
