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
    let hint: ReturnType<typeof setTimeout> | undefined;
    let disconnected = false;
    const unsub = store.on(
      StoreEvents.ConnectionChanged,
      (connected: boolean) => {
        // Read per event: the user can disconnect by hand after this mounted.
        const userDisconnected =
          localStorage.getItem('ws-disconnected') === '1';

        if (connected) {
          wasEverConnected.current = true;
          disconnected = false;
          clearTimeout(hint);
          hint = undefined;
          toast.dismiss('connection-status');
        } else if (
          wasEverConnected.current &&
          !userDisconnected &&
          !disconnected
        ) {
          disconnected = true;
          // A normal reconnect includes a one-second retry plus authentication.
          // Do not put a toast over editing controls while that settles.
          hint = setTimeout(() => {
            toast('Working offline — your changes are saved locally', {
              icon: OFFLINE_ICON,
              duration: 4000,
              id: 'connection-status',
            });
          }, 2_000);
        }
      },
    );

    return () => {
      clearTimeout(hint);
      unsub();
    };
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
