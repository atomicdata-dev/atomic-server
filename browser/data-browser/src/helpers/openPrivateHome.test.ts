import { beforeEach, expect, it, vi } from 'vitest';
import { core, type Resource, type Store } from '@tomic/lib';
import { openPrivateHome } from './openPrivateHome';
import { deviceHasDriveData } from './driveData';
import { restoreFromVault } from './managed/vaultAutoBackup';
vi.mock('./driveData', () => ({ deviceHasDriveData: vi.fn() }));
vi.mock('./originNode', () => ({ isOriginWithoutNode: () => true }));
vi.mock('./managed/vaultAutoBackup', () => ({ restoreFromVault: vi.fn() }));

const home = 'did:ad:home';
let agent: { subject: string } | undefined;
let store: Store;
let ensure: ReturnType<typeof vi.fn>;
let agentName: string | undefined;
beforeEach(() => {
  vi.resetAllMocks();
  agent = { subject: 'did:ad:agent:test' };
  agentName = undefined;
  ensure = vi.fn().mockResolvedValue(undefined);
  store = {
    getAgent: () => agent,
    privateDriveSubject: async () => home,
    getServerUrl: () => 'https://app.example',
    ensurePrivateDrive: ensure,
    getResource: async (subject: string) =>
      ({
        get: (prop: string) =>
          subject === agent?.subject && prop === core.properties.name
            ? agentName
            : undefined,
      }) as unknown as Resource,
  } as unknown as Store;
  vi.mocked(deviceHasDriveData).mockResolvedValue(false);
  vi.mocked(restoreFromVault).mockResolvedValue({
    status: 'no-backup',
    reason: 'no account session',
  });
});
it('never synthesizes someone else’s workspace', async () => {
  expect(await openPrivateHome(store, 'did:ad:other')).toBeUndefined();
  expect(ensure).not.toHaveBeenCalled();
  expect(restoreFromVault).not.toHaveBeenCalled();
});
it('preserves a readable home without writing defaults over it', async () => {
  vi.mocked(deviceHasDriveData).mockResolvedValue(true);
  expect(await openPrivateHome(store, home)).toBe('existing');
  expect(ensure).not.toHaveBeenCalled();
});
it('uses recovered data before considering creation', async () => {
  vi.mocked(deviceHasDriveData)
    .mockResolvedValueOnce(false)
    .mockResolvedValueOnce(true);
  expect(await openPrivateHome(store, home)).toBe('existing');
  expect(restoreFromVault).toHaveBeenCalled();
  expect(ensure).not.toHaveBeenCalled();
});
it('creates one local home for concurrent route effects', async () => {
  expect(
    await Promise.all([
      openPrivateHome(store, home),
      openPrivateHome(store, home),
    ]),
  ).toEqual(['created', 'created']);
  // Nameless account: the library's own default titles it, so nothing is
  // passed rather than a literal this file would have to keep translated.
  expect(ensure).toHaveBeenCalledExactlyOnceWith(undefined, {
    localOnly: true,
  });
});
it('titles the home after whoever it belongs to', async () => {
  agentName = '  Returning 1758681600000  ';
  expect(await openPrivateHome(store, home)).toBe('created');
  expect(ensure).toHaveBeenCalledExactlyOnceWith(
    "Returning 1758681600000's Drive",
    {
      localOnly: true,
    },
  );
});
it('falls back to the default title when the agent cannot be read', async () => {
  store.getResource = (async () => {
    throw new Error('offline');
  }) as unknown as Store['getResource'];
  expect(await openPrivateHome(store, home)).toBe('created');
  expect(ensure).toHaveBeenCalledExactlyOnceWith(undefined, {
    localOnly: true,
  });
});
it('does not require recovery to succeed before providing a place to work', async () => {
  vi.mocked(restoreFromVault).mockRejectedValue(new Error('offline'));
  expect(await openPrivateHome(store, home)).toBe('created');
});
it('does not create a home after the user switches identity', async () => {
  vi.mocked(restoreFromVault).mockImplementation(async () => {
    agent = { subject: 'did:ad:agent:other' };

    return { status: 'no-backup', reason: 'no account session' };
  });
  expect(await openPrivateHome(store, home)).toBeUndefined();
  expect(ensure).not.toHaveBeenCalled();
});
