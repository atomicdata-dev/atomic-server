// @vitest-environment jsdom
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { useVaultBackup } from './useVaultBackup';
import { recoverDriveKey, restoreDrive, type VaultCapableDb } from './vault';

vi.mock('./session', () => ({ getManagedAccount: async () => ({}) }));
vi.mock('./vault', async importOriginal => ({
  ...(await importOriginal<typeof import('./vault')>()),
  listVaultDrives: async () => [
    { drive_subject: 'drive', drive_pseudonym: 'vault', status: 'active' },
  ],
  getVaultState: async () => ({ confirmed_objects: 1 }),
  recoverDriveKey: vi.fn(),
  restoreDrive: vi.fn(),
}));

afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});

const inputs = {
  db: {} as VaultCapableDb,
  keys: {
    vaultGenerateKey: vi.fn(),
    vaultWrapKey: vi.fn(),
    vaultUnwrapKey: vi.fn(),
  },
  driveSubject: 'drive',
  agentSubject: 'agent',
  signer: {
    signBytes: async () => btoa(String.fromCharCode(...new Uint8Array(64))),
  },
  proofMessage: new Uint8Array([1]),
  devicePubkey: 'device',
};

it('manual restore passes the recovered epoch to the importer', async () => {
  const driveKey = new Uint8Array(32).fill(7);
  vi.mocked(recoverDriveKey).mockResolvedValue({ driveKey, keyEpoch: 4 });
  const { result } = renderHook(() => useVaultBackup(inputs));
  await waitFor(() => expect(result.current.status.state).toBe('on'));
  await act(async () => {
    await result.current.restore();
  });

  expect(restoreDrive).toHaveBeenCalledWith(
    expect.objectContaining({
      db: inputs.db,
      driveKey,
      keyEpoch: 4,
      drivePseudonym: 'vault',
      devicePubkey: 'device',
    }),
  );
});

it('a failed import cannot return a success result to the panel reload callback', async () => {
  vi.mocked(recoverDriveKey).mockResolvedValue({
    driveKey: new Uint8Array(32),
    keyEpoch: 1,
  });
  vi.mocked(restoreDrive).mockRejectedValue(
    new Error('Restore incomplete: 1 unreadable object'),
  );
  const { result } = renderHook(() => useVaultBackup(inputs));
  await waitFor(() => expect(result.current.status.state).toBe('on'));
  await act(async () => {
    expect(await result.current.restore()).toBeNull();
  });
  expect(result.current.error).toContain('Restore incomplete');
  expect(result.current.busy).toBe(false);
  expect(result.current.restoreProgress).toBeNull();
});

it('refreshes the key when another device re-keys an already-open panel', async () => {
  const oldKey = new Uint8Array(32).fill(4);
  const newKey = new Uint8Array(32).fill(5);
  vi.mocked(recoverDriveKey)
    .mockResolvedValueOnce({ driveKey: oldKey, keyEpoch: 4 })
    .mockResolvedValueOnce({ driveKey: newKey, keyEpoch: 5 });
  const { result } = renderHook(() => useVaultBackup(inputs));
  await waitFor(() => expect(result.current.status.state).toBe('on'));
  await act(async () => {
    await result.current.restore();
  });
  await act(async () => {
    await result.current.restore();
  });
  expect(restoreDrive).toHaveBeenLastCalledWith(
    expect.objectContaining({
      driveKey: newKey,
      keyEpoch: 5,
    }),
  );
});
