// @wc-ignore-file
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { loadVaultStorageReport } from './vaultStorageReport';
import { getManagedAccount } from './session';
import { getVaultUsage, listVaultDrives, listVaultObjects } from './vault';
vi.mock('./session', () => ({
  getManagedAccount: vi.fn(),
  accountAddress: (account: { email: string }) => account.email,
}));
vi.mock('./vault', () => ({
  getVaultUsage: vi.fn(),
  listVaultDrives: vi.fn(),
  listVaultObjects: vi.fn(),
}));
afterEach(() => vi.resetAllMocks());
beforeEach(() => vi.mocked(listVaultObjects).mockResolvedValue([]));
const drive = (id: string, used: number) => ({
  id,
  drive_pseudonym: id,
  drive_subject: id,
  agent_subject: `agent-${id}`,
  used_bytes: used,
  quota_bytes: 100,
});

it('includes other identities and retains listed bytes when one detail request fails', async () => {
  vi.mocked(getManagedAccount).mockResolvedValue({ email: 'owner' });
  vi.mocked(listVaultDrives).mockResolvedValue([
    drive('a', 10),
    drive('b', 90),
  ] as never);
  vi.mocked(getVaultUsage).mockImplementation(async id => {
    if (id === 'b') throw new Error('Unavailable');

    return { used_bytes: 15 } as never;
  });
  const report = await loadVaultStorageReport(new AbortController().signal);
  expect(report.workspaces.map(w => w.enrollment.id)).toEqual(['b', 'a']);
  expect(report.total_bytes).toBe(105);
  expect(report.workspaces[0].error).toBe('Unavailable');
  expect(report.workspaces[0].usage).toBeNull();
});
it('refuses a mixed report if the cookie account changes during reads', async () => {
  vi.mocked(getManagedAccount)
    .mockResolvedValueOnce({ email: 'first' })
    .mockResolvedValueOnce({ email: 'second' });
  vi.mocked(listVaultDrives).mockResolvedValue([]);
  await expect(
    loadVaultStorageReport(new AbortController().signal),
  ).rejects.toThrow('Account changed');
});
it('does not request inventories when signed out', async () => {
  vi.mocked(getManagedAccount).mockResolvedValue(null);
  await expect(
    loadVaultStorageReport(new AbortController().signal),
  ).rejects.toThrow('Sign in');
  expect(listVaultDrives).not.toHaveBeenCalled();
});
it('does not publish a cancelled read', async () => {
  const controller = new AbortController();
  vi.mocked(getManagedAccount).mockImplementation(async () => {
    controller.abort();

    return { email: 'owner' };
  });
  await expect(loadVaultStorageReport(controller.signal)).rejects.toThrow();
  expect(listVaultDrives).not.toHaveBeenCalled();
});
