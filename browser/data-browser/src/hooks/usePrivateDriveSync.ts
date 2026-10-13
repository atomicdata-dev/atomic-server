import { useEffect } from 'react';
import { StoreEvents, useDrive, useStore } from '@tomic/react';

/**
 * Keeps data from the signed-in person's private drive in sync while another
 * drive is open. Closes two gaps:
 *
 * 1. The socket only pushes the open drive. When that is a team drive, the
 *    private drive's commits (a Notification another device recorded) never
 *    reach this one, and a list would stay as it was at first load. So the
 *    private drive is subscribed to explicitly.
 * 2. A collection waits only briefly for the connection and then settles on
 *    what it has: nothing, on a device that holds none of the private drive.
 *    So `invalidateCollection` is called once connected, and again after a
 *    reconnect for what was missed.
 *
 * @param privateDrive Subject of the private drive, if known.
 * @param invalidateCollection Re-runs the collection that reads the private drive.
 */
export function usePrivateDriveSync(
  privateDrive: string | undefined,
  invalidateCollection: () => unknown,
): void {
  const store = useStore();
  const [activeDrive] = useDrive();

  useEffect(() => {
    if (!privateDrive || privateDrive === activeDrive) return;

    return store.subscribeLive(privateDrive);
  }, [store, privateDrive, activeDrive]);

  useEffect(
    () =>
      store.on(StoreEvents.ConnectionChanged, connected => {
        if (connected) void invalidateCollection();
      }),
    [store, invalidateCollection],
  );
}
