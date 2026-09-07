// Managed account + per-drive usage helpers, talking to the control-plane `/api`
// base (same endpoint as the other managed helpers).
import { getManagedAccount } from './managed/session';
import { getManagedApiBase } from './managed/api';
import { createManagedSyncEnrollment } from './managed/enrollment';

export type ManagedUser = {
  email: string;
  created_at: number;
};

export async function getManagedUser(): Promise<ManagedUser | null> {
  return getManagedAccount() as Promise<ManagedUser | null>;
}

export type DriveUsageInfo = {
  driveName: string | null;
  resourceCount: number;
  blobBytes: number;
  loroBytes: number;
  quotaBytes: number | null;
};

/**
 * Per-drive usage the managed node reports to the control plane (resource count
 * + bytes used), read from the signed-in user's enrollments. Returns null when
 * not signed in to Managed Sync, or when this drive isn't enrolled.
 */
export async function getDriveUsage(
  driveSubject: string,
): Promise<DriveUsageInfo | null> {
  if (!driveSubject || !(await getManagedAccount())) return null;

  const response = await fetch(`${getManagedApiBase()}/sync-enrollments`, {
    credentials: 'include',
  });

  if (!response.ok) return null;

  const body = (await response.json()) as unknown;
  const list = (
    Array.isArray(body)
      ? body
      : ((body as { enrollments?: unknown[] })?.enrollments ?? [])
  ) as Array<{
    drive_subject?: string;
    drive_name?: string;
    resource_count?: number;
    blob_bytes?: number;
    loro_bytes?: number;
    quota_bytes?: number;
  }>;

  const match = list.find(e => e.drive_subject === driveSubject);

  if (!match) return null;

  return {
    driveName: match.drive_name ?? null,
    resourceCount: match.resource_count ?? 0,
    blobBytes: match.blob_bytes ?? 0,
    loroBytes: match.loro_bytes ?? 0,
    quotaBytes: match.quota_bytes ?? null,
  };
}

/**
 * Enroll a drive for hosting. Delegates to `createManagedSyncEnrollment`, which
 * signs the control plane's challenge when given the agent, so there is only
 * one code path that talks to `POST /sync-enrollments`.
 */
export const createManagedEnrollment = createManagedSyncEnrollment;
