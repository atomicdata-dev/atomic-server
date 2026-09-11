import { beforeEach, expect, it, vi } from 'vitest';
const mocks = vi.hoisted(() => ({
  fetch: vi.fn(),
  validate: vi.fn(),
  tables: vi.fn(),
  apply: vi.fn(),
  ensure: vi.fn(),
  prepare: vi.fn(),
}));
vi.mock('@tomic/react', () => ({
  core: { properties: { name: 'name' } },
  dataBrowser: { classes: { folder: 'folder' } },
  applyPlan: mocks.apply,
  applyHostFromStore: () => ({}),
}));
vi.mock('@localthought/atomic-integrations/ui/GoogleCalendar', () => ({
  googleCalendarIntegration: { id: 'google-calendar' },
}));
vi.mock('./localThought', () => ({
  browserIntegrations: () => ({
    fetchRecords: mocks.fetch,
    validateConnection: mocks.validate,
  }),
  platformName: (name: string) => name,
}));
vi.mock('./localThoughtTables', () => ({ ensureImportTables: mocks.tables }));
vi.mock('./installationResources', () => ({
  ensureLocalInstallationResource: mocks.ensure,
}));
vi.mock('./localImportVerdict', () => ({
  localImportVerdict: async () => '{}',
}));
vi.mock('./runScript', () => ({ prepareFromVerdict: mocks.prepare }));
import {
  findInstallation,
  installLocalThought,
  refreshLocalThought,
  saveInstallation,
  type LocalThoughtInstallation,
} from './localThoughtSync';
const entry: LocalThoughtInstallation = {
  folder: 'folder',
  identity: 'identity',
  origin: 'https://proxy.example',
  drive: 'drive',
  actor: 'actor',
  platform: 'pets',
  connection: 'connection',
  constants: {},
};
let actor = 'actor';
const store = {
  getAgent: () => ({ subject: actor }),
  getDrive: () => 'drive',
  getLocalResource: async () => ({ hasClasses: () => true }),
};
beforeEach(() => {
  vi.clearAllMocks();
  actor = 'actor';
  const values = new Map<string, string>();
  vi.stubGlobal('localStorage', {
    get length() {
      return values.size;
    },
    key: (i: number) => [...values.keys()][i],
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
  });
  vi.stubGlobal('window', new EventTarget());
  const locks = new Set<string>();
  vi.stubGlobal('navigator', {
    locks: {
      request: async (
        key: string,
        options: unknown,
        callback?: (lock: unknown) => Promise<void>,
      ) => {
        const run = callback ?? (options as (lock: unknown) => Promise<void>);
        if (locks.has(key)) return run(null);
        locks.add(key);

        try {
          return await run({});
        } finally {
          locks.delete(key);
        }
      },
    },
  });
  mocks.fetch.mockResolvedValue({
    platform: 'pets',
    records: [],
    ontology: { terms: [] },
  });
  mocks.tables.mockResolvedValue({
    platform: 'pets',
    destinations: {},
    properties: {},
  });
  mocks.prepare.mockResolvedValue({ plan: { blocked: false } });
  mocks.apply.mockResolvedValue({ failed: 0, stoppedEarly: false });
  mocks.ensure.mockResolvedValue({ subject: 'folder' });
  mocks.validate.mockResolvedValue(undefined);
  saveInstallation(entry);
});
it('completes installation without fetching or applying records, and fails before folder creation on denied access', async () => {
  await installLocalThought(store as never, entry);
  expect(mocks.fetch).not.toHaveBeenCalled();
  expect(mocks.apply).not.toHaveBeenCalled();
  mocks.ensure.mockClear();
  mocks.validate.mockRejectedValue(new Error('HTTP 401'));
  await expect(installLocalThought(store as never, entry)).rejects.toThrow(
    '401',
  );
  expect(mocks.ensure).not.toHaveBeenCalled();
});
it('coalesces overlapping opens throughout fetching and applying', async () => {
  let finish!: () => void;
  mocks.fetch.mockImplementation(
    () =>
      new Promise(resolve => {
        finish = () => resolve({ platform: 'pets', records: [] });
      }),
  );
  const first = refreshLocalThought(store as never, entry);
  await refreshLocalThought(store as never, entry);
  expect(mocks.fetch).toHaveBeenCalledTimes(1);
  finish();
  await first;
  expect(mocks.apply).toHaveBeenCalledTimes(1);
  expect(findInstallation(store as never, 'table', 'folder')).toMatchObject({
    syncing: false,
    lastSuccess: expect.any(Number),
  });
});
it('keeps the last success and existing records on failure, then recovers on reopening', async () => {
  saveInstallation({ ...entry, lastSuccess: 42 });
  mocks.fetch.mockRejectedValueOnce(new Error('offline'));
  await refreshLocalThought(store as never, entry);
  expect(mocks.apply).not.toHaveBeenCalled();
  expect(findInstallation(store as never, 'folder')).toMatchObject({
    lastSuccess: 42,
    syncing: false,
    error: 'Error: offline',
  });
  await refreshLocalThought(store as never, entry);
  expect(findInstallation(store as never, 'folder')?.error).toBeUndefined();
  expect(mocks.apply).toHaveBeenCalledTimes(1);
});
it('does not apply a blocked import or data fetched for a previous signed-in account', async () => {
  mocks.prepare.mockResolvedValueOnce({
    plan: {
      blocked: true,
      problems: [{ message: 'Local edit conflicts with provider' }],
    },
  });
  await refreshLocalThought(store as never, entry);
  expect(mocks.apply).not.toHaveBeenCalled();
  expect(findInstallation(store as never, 'folder')?.error).toContain(
    'Local edit conflicts',
  );
  mocks.fetch.mockImplementationOnce(async () => {
    actor = 'another';

    return { platform: 'pets' };
  });
  await refreshLocalThought(store as never, entry);
  expect(mocks.apply).not.toHaveBeenCalled();
  expect(findInstallation(store as never, 'folder')).toBeUndefined();
});
