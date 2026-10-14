import { accountAddress, getManagedAccount } from './session';
import {
  getVaultUsage,
  listVaultDrives,
  listVaultObjects,
  type VaultEnrollment,
  type VaultObject,
  type VaultUsage,
} from './vault';

export type WorkspaceStorage = {
  enrollment: VaultEnrollment;
  usage: VaultUsage | null;
  objects: VaultObject[] | null;
  error: string | null;
};
export type VaultStorageReport = {
  generated_at: string;
  account: string;
  accountId: string;
  total_bytes: number;
  workspaces: WorkspaceStorage[];
};
export const workspaceBytes = (row: WorkspaceStorage) =>
  row.usage?.used_bytes ?? row.enrollment.used_bytes;

/** Owner-scoped metadata only. Never downloads backup bodies or changes storage. */
export async function loadVaultStorageReport(
  signal: AbortSignal,
): Promise<VaultStorageReport> {
  const account = await getManagedAccount({ fresh: true });
  signal.throwIfAborted();
  if (!account)
    throw new Error('Sign in to your account to inspect Cloud Vault storage.');
  const enrollments = await listVaultDrives(signal);
  const workspaces: WorkspaceStorage[] = [];

  // Bound metadata fan-out as well as payload downloads. An unavailable workspace
  // stays in the report with its last listed counter, never silently as zero.
  for (let i = 0; i < enrollments.length; i += 3) {
    signal.throwIfAborted();
    const batch = await Promise.all(
      enrollments.slice(i, i + 3).map(async enrollment => {
        const [usage, objects] = await Promise.allSettled([
          getVaultUsage(enrollment.drive_pseudonym, signal),
          listVaultObjects(enrollment.drive_pseudonym, signal),
        ]);

        return {
          enrollment,
          usage: usage.status === 'fulfilled' ? usage.value : null,
          objects: objects.status === 'fulfilled' ? objects.value : null,
          error:
            [usage, objects]
              .flatMap(result =>
                result.status === 'rejected'
                  ? [
                      result.reason instanceof Error
                        ? result.reason.message
                        : String(result.reason),
                    ]
                  : [],
              )
              .join('; ') || null,
        };
      }),
    );
    workspaces.push(...batch);
  }

  const current = await getManagedAccount({ fresh: true });
  signal.throwIfAborted();
  if (current?.email !== account.email)
    throw new Error('Account changed. Refresh to inspect its storage.');
  workspaces.sort((a, b) => workspaceBytes(b) - workspaceBytes(a));

  return {
    generated_at: new Date().toISOString(),
    account: accountAddress(account),
    accountId: account.email,
    total_bytes: workspaces.reduce((sum, row) => sum + workspaceBytes(row), 0),
    workspaces,
  };
}

export function downloadVaultStorageReport(report: VaultStorageReport) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }),
  );
  const link = document.createElement('a');
  link.href = url;
  link.download = 'cloud-vault-storage.json';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
