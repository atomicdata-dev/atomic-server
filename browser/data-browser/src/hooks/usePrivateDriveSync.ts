import { useEffect, useRef } from 'react';
import { StoreEvents, useDrive, useResource, useStore } from '@tomic/react';

/**
 * Keeps data from the signed-in person's private drive in sync while another
 * drive is open. Closes two gaps:
 *
 * 1. The socket only pushes the open drive. When that is a team drive, the
 *    private drive's commits (a Notification another device recorded) never
 *    reach this one, and a list would stay as it was at first load. So the
 *    private drive is subscribed to explicitly, once it has loaded.
 * 2. A collection waits only briefly for the connection and then settles on
 *    what it has: nothing, on a device that holds none of the private drive.
 *    So `invalidateCollection` is called once connected, and again after a
 *    reconnect for what was missed.
 *
 * @param privateDrive Subject of the private drive, if known.
 * @param invalidateCollection Optional. Re-runs the collection that reads the private drive.
 */
export function usePrivateDriveSync(
  privateDrive: string | undefined,
  invalidateCollection?: () => unknown,
): void {
  const store = useStore();
  const [activeDrive] = useDrive();
  // Load it: the socket holds the SUB until the drive is known to be readable
  // (it may not exist yet, e.g. a fresh agent), and sends it once it is.
  useResource(privateDrive);

  // Held in a ref so a callback that changes identity per render does not
  // resubscribe the listener below.
  const invalidateRef = useRef(invalidateCollection);
  useEffect(() => {
    invalidateRef.current = invalidateCollection;
  });

  useEffect(() => {
    if (!privateDrive) return;

    if (
      activeDrive &&
      store.normalizeSubject(privateDrive) ===
        store.normalizeSubject(activeDrive)
    ) {
      return;
    }

    return store.subscribeLive(privateDrive);
  }, [store, privateDrive, activeDrive]);

  useEffect(
    () =>
      store.on(StoreEvents.ConnectionChanged, connected => {
        if (connected) void invalidateRef.current?.();
      }),
    [store],
  );
}
