import {
  core,
  StoreEvents,
  notifications,
  useCollection,
  useResources,
  useStore,
  type Resource,
  type Collection,
} from '@tomic/react';
import { useEffect, useState } from 'react';
import { usePrivateDrive } from './usePrivateDrive';
import { usePrivateDriveSync } from './usePrivateDriveSync';
import {
  dedupeBySource,
  isUnread,
  readReceipts,
  type NotificationReceipts,
} from '../helpers/notifications/inbox';

const PAGE_SIZE = 100;

/**
 * The signed-in person's notifications, newest first, one per source, live.
 * Found by class in the private drive rather than by walking the Inbox, so
 * copies made by another device count as soon as they sync.
 */
export function useInbox(): {
  items: Resource[];
  receipts: NotificationReceipts;
  unread: number;
  ready: boolean;
  /** True while loading available rows and their members, including offline. */
  loading: boolean;
  privateDrive: string | undefined;
} {
  const { privateDrive } = usePrivateDrive();
  const store = useStore();
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
  usePrivateDriveSync(privateDrive, invalidateCollection);

  useEffect(() => {
    if (!ready || !privateDrive) return;
    let cancelled = false;
    const unsubscribe = store.on(StoreEvents.ConnectionChanged, connected => {
      const db = store.getClientDb();
      if (!connected || (db && !db.initError)) return;
      // Without OPFS there are no version vectors to reconcile. Re-query the
      // inbox and re-fetch cached members: membership alone misses read changes.
      void invalidateCollection()
        .then(async () => {
          const subjects = await collection.getAllMembers();
          if (cancelled) return;
          await Promise.all(
            subjects.map(subject => store.fetchResourceFromServer(subject)),
          );
        })
        .catch(error =>
          console.error('Could not refresh notifications:', error),
        );
    });

    return () => {
      cancelled = true;
      unsubscribe();
    };
  }, [store, privateDrive, ready, collection, invalidateCollection]);
  const [allMembers, setAllMembers] = useState<{
    collection: Collection;
    drive: string;
    subjects: string[];
  }>();

  useEffect(() => {
    if (!ready || !privateDrive) return;
    let cancelled = false;
    void collection
      // Rendering can use partial rows while the private drive reconciles.
      // Positive delivery/read receipts remain safe while more rows arrive.
      .getAllMembers()
      .then(subjects => {
        if (!cancelled)
          setAllMembers({ collection, drive: privateDrive, subjects });
      })
      .catch(error => {
        if (!cancelled) console.error('Could not read notifications:', error);
      });

    return () => {
      cancelled = true;
    };
  }, [store, collection, ready, privateDrive]);

  const membersReady =
    ready &&
    !!privateDrive &&
    allMembers?.collection === collection &&
    allMembers.drive === privateDrive;
  const resources = useResources(membersReady ? allMembers.subjects : []);

  const loaded = [...resources.values()].filter(
    r =>
      !r.loading &&
      !r.error &&
      r.hasClasses(notifications.classes.notification),
  );
  const homes = useResources(privateDrive ? [privateDrive] : []);
  const receipts = readReceipts([...homes.values()][0]);
  const items = dedupeBySource(loaded, receipts);
  const isReady = ready && !!privateDrive;

  return {
    items,
    receipts,
    unread: items.filter(item => isUnread(item, receipts)).length,
    ready: isReady,
    loading: !membersReady || [...resources.values()].some(r => r.loading),
    privateDrive,
  };
}
