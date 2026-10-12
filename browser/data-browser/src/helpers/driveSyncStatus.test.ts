import { describe, expect, it } from 'vitest';
import type { StoreSyncStatus } from '@tomic/lib';
import {
  deriveNodeStatuses,
  currentDriveSync,
  currentDriveValue,
  driveHostedByNode,
  hasHostedDriveConnection,
  shouldAutoEnroll,
} from './driveSyncStatus';

describe('drive-specific server status', () => {
  it('does not reuse another drive synchronization', () => {
    const status = {
      drive: 'did:ad:personal',
      serverConnected: true,
      pendingDirtyCount: 0,
      syncInProgress: false,
      lastDriveSync: { drive: 'did:ad:work', count: 28, timestamp: 100 },
    } as StoreSyncStatus;
    expect(deriveNodeStatuses(status).server).toBe('unknown');
  });
});

describe('Cloud Server requires evidence for the selected drive', () => {
  it('does not call a global managed connection hosting', () => {
    expect(hasHostedDriveConnection(true, true, false, undefined)).toBe(false);
    expect(hasHostedDriveConnection(false, true, true, 28)).toBe(false);
  });

  it('requires enrollment and a populated remote copy to claim hosting', () => {
    expect(hasHostedDriveConnection(true, true, true, undefined)).toBe(false);
    expect(hasHostedDriveConnection(true, true, false, 28)).toBe(false);
    expect(hasHostedDriveConnection(true, false, true, 28)).toBe(false);
    expect(hasHostedDriveConnection(true, true, null, 28)).toBe(false);
    expect(hasHostedDriveConnection(true, true, true, 28)).toBe(true);
  });

  it('discards usage or enrollment from another drive or server immediately', () => {
    const state = { drive: 'work', server: 'node1', value: true };
    expect(currentDriveValue(state, 'personal', 'node1')).toBeNull();
    expect(currentDriveValue(state, 'work', 'node2')).toBeNull();
    expect(currentDriveValue(state, 'work', 'node1')).toBe(true);
  });

  it('only exposes the current drive sync timestamp', () => {
    const status = {
      drive: 'personal',
      lastDriveSync: { drive: 'work', count: 28, timestamp: 100 },
    } as StoreSyncStatus;
    expect(currentDriveSync(status)).toBeUndefined();
    expect(currentDriveSync({ ...status, drive: 'work' })?.timestamp).toBe(100);
  });
});

describe('driveHostedByNode', () => {
  const synced = {
    drive: 'did:ad:ontola',
    serverConnected: true,
    pendingDirtyCount: 0,
    syncInProgress: false,
    lastDriveSync: { drive: 'did:ad:ontola', count: 12, timestamp: 100 },
  } as StoreSyncStatus;
  const hosted = {
    managed: true,
    liveSyncedDrive: true,
    refusedByServer: false,
    status: synced,
    resourceCount: 12,
  };

  it('sees a drive synced with a managed node as hosted, with no account', () => {
    expect(driveHostedByNode(hosted)).toBe(true);
  });

  it('does not count a self-hosted node', () => {
    expect(driveHostedByNode({ ...hosted, managed: false })).toBe(false);
  });

  it('waits for this drive to finish syncing', () => {
    expect(
      driveHostedByNode({
        ...hosted,
        status: {
          ...synced,
          lastDriveSync: { drive: 'did:ad:other', count: 3, timestamp: 1 },
        },
      }),
    ).toBe(false);
  });

  it('does not count a refused, offline or empty drive', () => {
    expect(driveHostedByNode({ ...hosted, refusedByServer: true })).toBe(false);
    expect(
      driveHostedByNode({
        ...hosted,
        status: { ...synced, serverConnected: false },
      }),
    ).toBe(false);
    expect(driveHostedByNode({ ...hosted, resourceCount: 0 })).toBe(false);
  });
});

describe('shouldAutoEnroll', () => {
  const base = {
    accountEnrolled: true,
    nodeInfoLoaded: true,
    currentServerManaged: false,
    paidPlanActive: false,
  };

  it('does not re-enroll before the server said whether it is managed', () => {
    expect(shouldAutoEnroll({ ...base, nodeInfoLoaded: false })).toBe(false);
  });

  it('does not re-enroll a drive already on a managed node', () => {
    expect(shouldAutoEnroll({ ...base, currentServerManaged: true })).toBe(
      false,
    );
  });

  it('switches an enrolled drive that this device has not switched to', () => {
    expect(shouldAutoEnroll(base)).toBe(true);
  });

  it('enrolls a paid drive that is not enrolled yet', () => {
    expect(
      shouldAutoEnroll({
        ...base,
        accountEnrolled: false,
        paidPlanActive: true,
      }),
    ).toBe(true);
    expect(shouldAutoEnroll({ ...base, accountEnrolled: false })).toBe(false);
    expect(shouldAutoEnroll({ ...base, accountEnrolled: null })).toBe(false);
  });
});
