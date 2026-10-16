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
  // Node synchronization is shown independently in Devices. Data on a managed
  // node alone does not prove this account has hosting enabled for this drive.
  return (
    liveSyncedDrive && managed && enrolled === true && (resourceCount ?? 0) > 0
  );
}

/**
 * Is this drive hosted on Cloud Server, as the node itself shows it?
 *
 * Hosting belongs to the drive, not to whoever is looking. A managed node only
 * accepts drives that are enrolled and active, and any member can read the
 * drive's usage from it. So a drive this device has finished syncing with a
 * managed node, and that holds data there, is hosted for everyone with
 * access, whichever account pays for it and whether or not this person is
 * signed in to the portal. When the node reports `enrolled` that is the
 * answer; an older node that does not is judged by whether it holds data. The evidence is the drive's own usage, read from
 * the node with this agent's read rights, so another drive's sync proves
 * nothing. It does not wait for this device's first sync to finish: the node
 * already answers for the drive. Not-enrolled refusals are excluded.
 */
export function driveHostedByNode(input: {
  managed: boolean;
  liveSyncedDrive: boolean;
  refusedByServer: boolean;
  status: StoreSyncStatus;
  resourceCount: number | undefined;
  /** The node's own answer from `/drive-usage`; undefined on an older node. */
  enrolled?: boolean;
}): boolean {
  // The node saying whether it admits the drive beats inferring it from data:
  // a drive whose plan was switched off keeps its data on the node.
  const nodeHoldsDrive = input.enrolled ?? (input.resourceCount ?? 0) > 0;

  return (
    input.managed &&
    input.liveSyncedDrive &&
    !input.refusedByServer &&
    input.status.serverConnected &&
    nodeHoldsDrive
  );
}

/**
 * Should the Sync page start Cloud Server for this drive by itself?
 *
 * An account that already enrolled the drive only needs a switch when this
 * device still points at some other server. Whether the current server is a
 * managed node is only known once `/server` has answered (`nodeInfoLoaded`);
 * until then "not managed" is just the default, and acting on it would
 * re-enroll and reconnect a drive that is already hosted here (a spurious
 * "working offline" toast and a "Connected to Cloud Server" toast on every
 * visit). A paid-but-unenrolled drive has to be enrolled either way.
 */
export function shouldAutoEnroll(input: {
  accountEnrolled: boolean | null;
  nodeInfoLoaded: boolean;
  currentServerManaged: boolean;
  paidPlanActive: boolean;
}): boolean {
  if (input.accountEnrolled === true) {
    return input.nodeInfoLoaded && !input.currentServerManaged;
  }

  return input.accountEnrolled === false && input.paidPlanActive;
}
