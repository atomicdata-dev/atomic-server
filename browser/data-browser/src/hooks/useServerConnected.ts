import { StoreEvents, useStore } from '@tomic/react';
import { useSyncExternalStore } from 'react';

export function useServerConnected(): boolean {
  const store = useStore();

  return useSyncExternalStore(
    onChange => store.on(StoreEvents.ConnectionChanged, onChange),
    () => store.serverConnected,
  );
}
