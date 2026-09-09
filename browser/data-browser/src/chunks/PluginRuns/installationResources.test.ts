import { expect, it, vi } from 'vitest';
const { query } = vi.hoisted(() => ({ query: vi.fn() }));
vi.mock('@tomic/react', () => ({
  core: { properties: { localId: 'localId', parent: 'parent', isA: 'isA' } },
  readConnectionSubjects: query,
}));
import { ensureInstallationResource } from './installationResources';
it('recovers a committed setup step after its response was lost', async () => {
  let persisted = false;
  const resource = {
    subject: 'saved',
    get: (p: string) => ({ parent: 'parent', isA: ['class'] })[p],
    save: async () => {
      persisted = true;
      throw new Error('lost receipt');
    },
  };
  query.mockImplementation(async () => (persisted ? ['saved'] : []));
  const store = {
    getResource: async () => resource,
    newResource: vi.fn(async () => resource),
  };
  const options = {
    parent: 'parent',
    localId: 'step',
    isA: ['class'],
    propVals: {},
  };
  expect(
    await ensureInstallationResource(store as never, 'drive', options),
  ).toBe(resource);
  expect(
    await ensureInstallationResource(store as never, 'drive', options),
  ).toBe(resource);
  expect(store.newResource).toHaveBeenCalledTimes(1);
});
it('never interprets a failed identity query as permission to create', async () => {
  query.mockRejectedValue(new Error('offline'));
  const store = { newResource: vi.fn() };
  await expect(
    ensureInstallationResource(store as never, 'drive', {
      parent: 'parent',
      localId: 'step',
      isA: [],
      propVals: {},
    }),
  ).rejects.toThrow('offline');
  expect(store.newResource).not.toHaveBeenCalled();
});

it('uses complete local identities without a server and refuses a missing local DB', async () => {
  const { ensureLocalInstallationResource } =
    await import('./installationResources');
  const resource = {
    get: (p: string) => ({ parent: 'parent', isA: ['class'] })[p],
  };
  const queryLocalDb = vi
    .fn()
    .mockResolvedValue({ subjects: ['saved'], count: 1 });
  const store = {
    queryLocalDb,
    getResource: async () => resource,
    newResource: vi.fn(),
  };
  const options = {
    parent: 'parent',
    localId: 'step',
    isA: ['class'],
    propVals: {},
  };
  expect(
    await ensureLocalInstallationResource(store as never, 'drive', options),
  ).toBe(resource);
  queryLocalDb.mockResolvedValue(null);
  await expect(
    ensureLocalInstallationResource(store as never, 'drive', options),
  ).rejects.toThrow('Local installation query');
  queryLocalDb.mockResolvedValue({ subjects: [], count: 1 });
  await expect(
    ensureLocalInstallationResource(store as never, 'drive', options),
  ).rejects.toThrow('Local installation query');
  expect(store.newResource).not.toHaveBeenCalled();
});
