import { useEffect } from 'react';
import {
  core,
  notifications,
  StoreEvents,
  useCollection,
  useCollectionPage,
  useDrive,
  useResources,
  useStore,
  type Resource,
} from '@tomic/react';
import { usePrivateDrive } from './usePrivateDrive';
import { dedupeBySource, isUnread } from '../helpers/notifications/inbox';

const PAGE_SIZE = 100;

/**
 * The signed-in person's notifications, newest first, one per source, live.
 * Found by class in the private drive rather than by walking the Inbox, so
 * copies made by another device count as soon as they sync.
 */
export function useInbox(): {
  items: Resource[];
  unread: number;
  ready: boolean;
  /** True until the list is known: the query ran and every member loaded. */
  loading: boolean;
  privateDrive: string | undefined;
} {
  const store = useStore();
  const { privateDrive } = usePrivateDrive();
  const [activeDrive] = useDrive();
  const { collection, ready, invalidateCollection } = useCollection(
    {
      property: core.properties.isA,
      value: notifications.classes.notification,
      drive: privateDrive,
      sort_by: notifications.properties.occurredAt,
      sort_desc: true,
    },
    { pageSize: PAGE_SIZE },
  );

  // The socket only pushes the open drive. When that is a team drive, the
  // private drive's commits (a Notification another device recorded) never
  // reach this one, and the list would stay as it was at first load.
  useEffect(() => {
    if (!privateDrive || privateDrive === activeDrive) return;

    return store.subscribeLive(privateDrive);
  }, [store, privateDrive, activeDrive]);

  // A collection waits only briefly for the connection and then settles on
  // what it has: nothing, on a device that holds none of the private drive.
  // Ask again once connected, and after a reconnect for what was missed.
  useEffect(
    () =>
      store.on(StoreEvents.ConnectionChanged, connected => {
        if (connected) void invalidateCollection();
      }),
    [store, invalidateCollection],
  );

  const members = useCollectionPage(collection, 0);
  const resources = useResources(privateDrive ? members : []);

  const loaded = [...resources.values()].filter(
    r =>
      !r.loading &&
      !r.error &&
      r.hasClasses(notifications.classes.notification),
  );
  const items = dedupeBySource(loaded);
  const isReady = ready && !!privateDrive;

  return {
    items,
    unread: items.filter(isUnread).length,
    ready: isReady,
    loading: !isReady || [...resources.values()].some(r => r.loading),
    privateDrive,
  };
}
