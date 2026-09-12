import { useEffect, useRef } from 'react';
import { useOnline } from '../hooks/useOnline';
import toast from 'react-hot-toast';
import { StoreEvents, useStore } from '@tomic/react';
import { MdSignalWifiOff } from 'react-icons/md';

const OFFLINE_ICON = <MdSignalWifiOff />;

/**
 * No longer renders a visible element. Just shows friendly toasts
 * when connection state changes. The sync page handles detailed status.
 */
export function NetworkIndicator() {
  const isOnline = useOnline();
  const store = useStore();
  const wasEverConnected = useRef(false);
  const shownOfflineHint = useRef(false);

  // Show a one-time hint if the user manually disconnected
  useEffect(() => {
    if (shownOfflineHint.current) return;

    if (localStorage.getItem('ws-disconnected') === '1') {
      shownOfflineHint.current = true;
      toast('Running in offline mode. Reconnect in the sync menu.', {
        icon: OFFLINE_ICON,
        duration: 5000,
        id: 'offline-hint',
      });
    }
  }, []);

  useEffect(() => {
    const userDisconnected = localStorage.getItem('ws-disconnected') === '1';

    const unsub = store.on(
      StoreEvents.ConnectionChanged,
      (connected: boolean) => {
        if (connected) {
          wasEverConnected.current = true;
          toast.dismiss('connection-status');
        } else if (wasEverConnected.current && !userDisconnected) {
          toast('Working offline — your changes are saved locally', {
            icon: OFFLINE_ICON,
            duration: 4000,
            id: 'connection-status',
          });
        }
      },
    );

    return unsub;
  }, [store]);

  useEffect(() => {
    if (!isOnline) {
      toast('No internet — your changes are saved locally', {
        icon: OFFLINE_ICON,
        duration: 4000,
        id: 'connection-status',
      });
    }
  }, [isOnline]);

  return null;
}
