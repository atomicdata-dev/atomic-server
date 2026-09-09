import { describe, expect, it } from 'vitest';
import type { StoreSyncStatus } from '@tomic/lib';
import {
  deriveNodeStatuses,
  currentDriveSync,
  currentDriveValue,
  hasHostedDriveConnection,
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

  it('recognizes an enrolled drive and a colleague with node-confirmed data', () => {
    expect(hasHostedDriveConnection(true, true, true, undefined)).toBe(true);
    expect(hasHostedDriveConnection(true, true, false, 28)).toBe(true);
    expect(hasHostedDriveConnection(true, false, true, 28)).toBe(false);
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
