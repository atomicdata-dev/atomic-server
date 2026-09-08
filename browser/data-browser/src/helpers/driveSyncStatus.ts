import type { StoreSyncStatus } from '@tomic/lib';

export type NodeStatus =
  | 'synced'
  | 'syncing'
  | 'unsynced'
  | 'offline'
  | 'unknown';

export function deriveNodeStatuses(status: StoreSyncStatus): {
  local: NodeStatus;
  server: NodeStatus;
  line: NodeStatus;
} {
  const local: NodeStatus = 'synced';

  if (!status.serverConnected) {
    return {
      local,
      server: 'offline',
      line: 'offline',
    };
  }

  if (status.syncInProgress) {
    return { local, server: 'syncing', line: 'syncing' };
  }

  if (status.pendingDirtyCount > 0) {
    return { local, server: 'unsynced', line: 'unsynced' };
  }

  // Only claim "synced" if we've actually completed a drive sync.
  // Otherwise we're connected but haven't confirmed the data matches.
  if (!currentDriveSync(status)) {
    return { local, server: 'unknown', line: 'unknown' };
  }

  return { local, server: 'synced', line: 'synced' };
}

export function currentDriveSync(status: StoreSyncStatus) {
  return status.drive && status.lastDriveSync?.drive === status.drive
    ? status.lastDriveSync
    : undefined;
}

export type ScopedDriveValue<T> = { drive: string; server: string; value: T };

export function currentDriveValue<T>(
  state: ScopedDriveValue<T> | null,
  drive: string | undefined,
  server: string,
): T | null {
  return state?.drive === drive && state?.server === server
    ? state.value
    : null;
}

export function hasHostedDriveConnection(
  liveSyncedDrive: boolean,
  managed: boolean,
  enrolled: boolean | null,
  resourceCount: number | undefined,
): boolean {
  // A colleague can verify the shared drive directly on its node without
  // access to the owner's billing account. A global connection is not proof.
  return (
    liveSyncedDrive &&
    managed &&
    (enrolled === true || (resourceCount ?? 0) > 0)
  );
}
