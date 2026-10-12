import { afterEach, expect, it, vi } from 'vitest';

const db = vi.hoisted(() => ({
  indexMigrationPending: vi.fn(),
  migrateIndexKeysStep: vi.fn(),
  messageMigrationPending: vi.fn(),
  migrateMessagesStep: vi.fn(),
  aiChatMigrationPending: vi.fn(),
  migrateAiChatsStep: vi.fn(),
  conversationMigrationPending: vi.fn(),
  migrateConversationsStep: vi.fn(),
}));
vi.mock('./client-db-open.js', () => ({
  openClientDb: async () => ({ db }),
  isStorageBlockedDbError: () => false,
}));

afterEach(() => {
  vi.unstubAllGlobals();
  vi.resetModules();
  vi.resetAllMocks();
});

it('rebuilds the indexes in slices before init is acknowledged, reporting each one', async () => {
  const steps = [
    { done: 100, total: 250, finished: false },
    { done: 200, total: 250, finished: false },
    { done: 250, total: 250, finished: true },
  ];
  db.indexMigrationPending.mockReturnValue(true);
  db.migrateIndexKeysStep.mockImplementation(() =>
    JSON.stringify(steps.shift()),
  );

  const posted: Array<Record<string, unknown>> = [];
  const worker = {
    onmessage: null as unknown as (event: unknown) => void,
    postMessage: vi.fn((value: Record<string, unknown>) => posted.push(value)),
  };
  vi.stubGlobal('self', worker);
  await import('./client-db.worker.js');

  worker.onmessage({
    data: {
      id: 1,
      type: 'init',
      wasmUrl: 'data:text/javascript,export default async function() {}',
    },
  });
  await vi.waitFor(() => expect(posted.some(m => m.id === 1)).toBe(true));

  const progress = posted
    .filter(m => m.type === 'migration-progress')
    .map(m => [m.done, m.total, m.finished]);
  expect(progress).toEqual([
    [0, 0, false],
    [100, 250, false],
    [200, 250, false],
    [250, 250, true],
  ]);
  // The acknowledgement comes after the last slice.
  expect(posted.at(-1)).toMatchObject({ id: 1, type: 'ok' });
  expect(db.migrateIndexKeysStep).toHaveBeenCalledWith(100);
});

it('does nothing for a database that is already current', async () => {
  db.indexMigrationPending.mockReturnValue(false);
  const posted: Array<Record<string, unknown>> = [];
  const worker = {
    onmessage: null as unknown as (event: unknown) => void,
    postMessage: vi.fn((value: Record<string, unknown>) => posted.push(value)),
  };
  vi.stubGlobal('self', worker);
  await import('./client-db.worker.js');

  worker.onmessage({
    data: {
      id: 1,
      type: 'init',
      wasmUrl: 'data:text/javascript,export default async function() {}',
    },
  });
  await vi.waitFor(() => expect(posted.some(m => m.id === 1)).toBe(true));

  expect(posted.some(m => m.type === 'migration-progress')).toBe(false);
  expect(db.migrateIndexKeysStep).not.toHaveBeenCalled();
});

it('moves chat messages into pages after the index rebuild, for the local-only drives only', async () => {
  db.indexMigrationPending.mockReturnValue(false);
  db.messageMigrationPending.mockReturnValue(true);
  const steps = [
    { done: 500, total: 700, finished: false },
    { done: 700, total: 700, finished: true },
  ];
  db.migrateMessagesStep.mockImplementation(async () =>
    JSON.stringify(steps.shift()),
  );

  const posted: Array<Record<string, unknown>> = [];
  const worker = {
    onmessage: null as unknown as (event: unknown) => void,
    postMessage: vi.fn((value: Record<string, unknown>) => posted.push(value)),
  };
  vi.stubGlobal('self', worker);
  await import('./client-db.worker.js');

  worker.onmessage({
    data: {
      id: 1,
      type: 'init',
      wasmUrl: 'data:text/javascript,export default async function() {}',
      localOnlyDrives: ['did:ad:local'],
    },
  });
  await vi.waitFor(() => expect(posted.some(m => m.id === 1)).toBe(true));

  expect(
    posted
      .filter(m => m.type === 'migration-progress')
      .map(m => [m.phase, m.done, m.total, m.finished]),
  ).toEqual([
    ['messages', 0, 0, false],
    ['messages', 500, 700, false],
    ['messages', 700, 700, true],
  ]);
  // The page's local-only drives decide where pages are written.
  expect(db.migrateMessagesStep).toHaveBeenCalledWith(
    500,
    JSON.stringify(['did:ad:local']),
  );
  expect(posted.at(-1)).toMatchObject({ id: 1, type: 'ok' });
});

it('writes no pages when no drive is known to be local-only: it only cleans up', async () => {
  db.indexMigrationPending.mockReturnValue(false);
  db.messageMigrationPending.mockReturnValue(true);
  db.migrateMessagesStep.mockResolvedValue(
    JSON.stringify({ done: 3, total: 3, finished: true }),
  );

  const posted: Array<Record<string, unknown>> = [];
  const worker = {
    onmessage: null as unknown as (event: unknown) => void,
    postMessage: vi.fn((value: Record<string, unknown>) => posted.push(value)),
  };
  vi.stubGlobal('self', worker);
  await import('./client-db.worker.js');

  worker.onmessage({
    data: {
      id: 1,
      type: 'init',
      wasmUrl: 'data:text/javascript,export default async function() {}',
    },
  });
  await vi.waitFor(() => expect(posted.some(m => m.id === 1)).toBe(true));

  // An empty list: the store creates nothing and drops cached messages that
  // already have their entry (the Rust side of this is
  // `a_cache_of_a_hosted_drive_only_drops_messages_that_have_their_entry`).
  expect(db.migrateMessagesStep).toHaveBeenCalledWith(500, '[]');
});

it('moves the messages of AI chats after the group chats, with the same drives', async () => {
  db.indexMigrationPending.mockReturnValue(false);
  db.messageMigrationPending.mockReturnValue(false);
  db.aiChatMigrationPending.mockReturnValue(true);
  db.migrateAiChatsStep.mockResolvedValue(
    JSON.stringify({ done: 40, total: 40, finished: true }),
  );

  const posted: Array<Record<string, unknown>> = [];
  const worker = {
    onmessage: null as unknown as (event: unknown) => void,
    postMessage: vi.fn((value: Record<string, unknown>) => posted.push(value)),
  };
  vi.stubGlobal('self', worker);
  await import('./client-db.worker.js');

  worker.onmessage({
    data: {
      id: 1,
      type: 'init',
      wasmUrl: 'data:text/javascript,export default async function() {}',
      localOnlyDrives: ['did:ad:local'],
    },
  });
  await vi.waitFor(() => expect(posted.some(m => m.id === 1)).toBe(true));

  expect(db.migrateMessagesStep).not.toHaveBeenCalled();
  expect(db.migrateAiChatsStep).toHaveBeenCalledWith(
    500,
    JSON.stringify(['did:ad:local']),
  );
  expect(
    posted
      .filter(m => m.type === 'migration-progress')
      .map(m => [m.phase, m.done, m.total, m.finished]),
  ).toEqual([
    ['messages', 0, 0, false],
    ['messages', 40, 40, true],
  ]);
});

it('moves the messages of conversations last, with the same drives', async () => {
  db.indexMigrationPending.mockReturnValue(false);
  db.messageMigrationPending.mockReturnValue(false);
  db.aiChatMigrationPending.mockReturnValue(false);
  db.conversationMigrationPending.mockReturnValue(true);
  db.migrateConversationsStep.mockResolvedValue(
    JSON.stringify({ done: 12, total: 12, finished: true }),
  );

  const posted: Array<Record<string, unknown>> = [];
  const worker = {
    onmessage: null as unknown as (event: unknown) => void,
    postMessage: vi.fn((value: Record<string, unknown>) => posted.push(value)),
  };
  vi.stubGlobal('self', worker);
  await import('./client-db.worker.js');

  worker.onmessage({
    data: {
      id: 1,
      type: 'init',
      wasmUrl: 'data:text/javascript,export default async function() {}',
      localOnlyDrives: ['did:ad:local'],
    },
  });
  await vi.waitFor(() => expect(posted.some(m => m.id === 1)).toBe(true));

  expect(db.migrateMessagesStep).not.toHaveBeenCalled();
  expect(db.migrateAiChatsStep).not.toHaveBeenCalled();
  expect(db.migrateConversationsStep).toHaveBeenCalledWith(
    500,
    JSON.stringify(['did:ad:local']),
  );
  expect(
    posted
      .filter(m => m.type === 'migration-progress')
      .map(m => [m.phase, m.done, m.total, m.finished]),
  ).toEqual([
    ['messages', 0, 0, false],
    ['messages', 12, 12, true],
  ]);
});
