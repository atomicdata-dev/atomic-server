import { useEffect, useState, type JSX } from 'react';
import { StoreEvents, type StoreSyncStatus, useStore } from '@tomic/react';
import { FaWifi, FaArrowsRotate, FaCircleExclamation } from 'react-icons/fa6';
import { MdSignalWifiOff } from 'react-icons/md';
import { styled, keyframes } from 'styled-components';

/** The store's sync status, kept up to date as connection and sync change. */
export function useSyncStatus(): StoreSyncStatus {
  const store = useStore();
  const [status, setStatus] = useState<StoreSyncStatus>(() =>
    store.getSyncStatus(),
  );

  useEffect(() => {
    const refresh = () => setStatus(store.getSyncStatus());
    const unsubConnection = store.on(StoreEvents.ConnectionChanged, refresh);
    const unsubSync = store.on(StoreEvents.SyncStatusChanged, next =>
      setStatus(next),
    );
    const unsubDrive = store.on(StoreEvents.DriveChanged, refresh);
    const unsubServer = store.on(StoreEvents.ServerURLChanged, refresh);

    return () => {
      unsubConnection();
      unsubSync();
      unsubDrive();
      unsubServer();
    };
  }, [store]);

  return status;
}

export function getSyncIcon(status: StoreSyncStatus): JSX.Element {
  if (!status.serverConnected) {
    return (
      <OfflineIcon>
        <MdSignalWifiOff title='Offline' />
      </OfflineIcon>
    );
  }

  if (status.syncInProgress) {
    return (
      <SpinningIcon aria-hidden>
        <FaArrowsRotate />
      </SpinningIcon>
    );
  }

  if (status.blockedCount > 0) {
    return (
      <WarningIcon>
        <FaCircleExclamation title='Changes could not sync' />
      </WarningIcon>
    );
  }

  if (status.pendingDirtyCount > 0) {
    return (
      <WarningIcon>
        <FaCircleExclamation title='Changes pending' />
      </WarningIcon>
    );
  }

  return <FaWifi title='Connected' />;
}

/**
 * Whether the sidebar shows its warning icon: changes that could not sync, or
 * that wait with nothing else going on. The Sync page's banner explains it.
 */
export function hasSyncWarning(status: StoreSyncStatus): boolean {
  return (
    status.serverConnected &&
    !status.syncInProgress &&
    (status.blockedCount > 0 || status.pendingDirtyCount > 0)
  );
}

export function getSyncLabel(status: StoreSyncStatus): string {
  if (!status.serverConnected) return 'Offline';
  if (status.syncInProgress) return 'Syncing...';

  if (status.blockedCount > 0)
    return `${status.blockedCount} changes could not sync (no access)`;

  if (status.pendingDirtyCount > 0)
    return `${status.pendingDirtyCount} changes pending`;

  return 'Connected';
}

const spin = keyframes`
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
`;

const SpinningIcon = styled.span`
  display: inline-flex;
  animation: ${spin} 1s linear infinite;
`;

const WarningIcon = styled.span`
  color: ${p => p.theme.colors.warning};
  display: inline-flex;
`;

const OfflineIcon = styled.span`
  color: ${p => p.theme.colors.alert};
  display: inline-flex;
`;
