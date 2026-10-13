// @wc-ignore-file
// The Inbox: one per person, in their private drive, holding Notifications.
//
// For now the person's own apps fill it: whichever of their devices has the
// app open when a message arrives records it. Later other servers and
// services deliver into it too (an append-only right on the Inbox), which is
// why a Notification is a resource and not a local list.
//
// Several devices can be open at once and each sees the same message, so
// recording is "check, then create". Two devices can still both create one
// (signatures here aren't deterministic, so the subject can't be derived from
// the message); the list shows one item per source, read when any copy is.
import {
  core,
  Datatype,
  dataBrowser,
  notifications,
  CollectionBuilder,
  type Resource,
  type Store,
} from '@tomic/react';
import { getOrCreateDriveLocation } from '../standardLocations';

export type NotificationKind = 'chat' | 'comment' | 'reply';

export interface NotificationRecord {
  /** The resource that caused it: the Message. */
  source: string;
  /** Where clicking it goes: the chat, or the commented resource. */
  about: string;
  kind: NotificationKind;
  actor: string;
  title: string;
  body: string;
  occurredAt: number;
  /** Set when the person saw it already, e.g. they were looking at the chat. */
  read?: boolean;
}

const inboxRequests = new WeakMap<Store, Map<string, Promise<string>>>();

/** The Inbox in the private drive, created on first use. */
export async function getOrCreateInbox(
  store: Store,
  privateDrive: string,
): Promise<string> {
  let requests = inboxRequests.get(store);

  if (!requests) {
    requests = new Map();
    inboxRequests.set(store, requests);
  }

  const pending = requests.get(privateDrive);
  if (pending) return pending;

  const request = getOrCreateDriveLocation(
    store,
    privateDrive,
    notifications.properties.inbox,
    { isA: notifications.classes.inbox, name: 'Inbox' },
  );
  requests.set(privateDrive, request);
  // Forget failures, so a later message can try again.
  request.catch(() => requests.delete(privateDrive));

  return request;
}

/** The Notifications recorded for a source, in this private drive. */
export async function findNotificationsFor(
  store: Store,
  privateDrive: string,
  source: string,
): Promise<string[]> {
  const collection = new CollectionBuilder(store)
    .setProperty(notifications.properties.notificationSource)
    .setValue(source)
    .setFilters([
      {
        property: core.properties.isA,
        value: notifications.classes.notification,
      },
    ])
    .setDrive(privateDrive)
    .setPageSize(10)
    .build();
  await collection.waitForReady();

  return collection.getAllMembers();
}

/**
 * Records a notification in the Inbox, unless one for the same source is
 * there already. Returns its subject.
 */
export async function recordNotification(
  store: Store,
  privateDrive: string,
  record: NotificationRecord,
): Promise<string> {
  const inbox = await getOrCreateInbox(store, privateDrive);

  const [existing] = await findNotificationsFor(
    store,
    privateDrive,
    record.source,
  );

  if (existing) {
    if (record.read) await markRead(store, [existing]);

    return existing;
  }

  const propVals: Record<string, string | number> = {
    [core.properties.name]: record.title,
    [core.properties.description]: record.body,
    [dataBrowser.properties.about]: record.about,
    [notifications.properties.notificationSource]: record.source,
    [notifications.properties.notificationKind]: record.kind,
    [notifications.properties.actor]: record.actor,
    [notifications.properties.occurredAt]: record.occurredAt,
  };

  if (record.read) propVals[notifications.properties.readAt] = Date.now();

  const resource = await store.newResource({
    parent: inbox,
    isA: notifications.classes.notification,
    propVals,
    // Servers that predate this ontology can't describe these properties.
    propDatatypes: {
      [notifications.properties.notificationSource]: Datatype.ATOMIC_URL,
      [notifications.properties.notificationKind]: Datatype.STRING,
      [notifications.properties.actor]: Datatype.ATOMIC_URL,
      [notifications.properties.occurredAt]: Datatype.TIMESTAMP,
      [notifications.properties.readAt]: Datatype.TIMESTAMP,
    },
  });
  await resource.save();
  store.notifyResourceManuallyCreated(resource);

  return resource.subject;
}

export const isUnread = (notification: Resource): boolean =>
  notification.get(notifications.properties.readAt) === undefined;

/**
 * Marks the given Notifications read, skipping those that already are, and
 * those about something that happened after `upTo`.
 */
export async function markRead(
  store: Store,
  subjects: string[],
  upTo = Number.POSITIVE_INFINITY,
): Promise<void> {
  const now = Date.now();

  await Promise.all(
    subjects.map(async subject => {
      const notification = await store.getResource(subject);

      if (notification.error || !isUnread(notification)) return;
      if (occurredAt(notification) > upTo) return;

      await notification.set(notifications.properties.readAt, now, false);
      await notification.save();
    }),
  );
}

/**
 * Marks every Notification about `target` read, e.g. once it was opened.
 * Only what happened up to `upTo`: the query can take a while, and a message
 * that arrives meanwhile, while the person has moved on, is still news.
 */
export async function markReadAbout(
  store: Store,
  privateDrive: string,
  target: string,
  upTo = Date.now(),
): Promise<void> {
  const collection = new CollectionBuilder(store)
    .setProperty(dataBrowser.properties.about)
    .setValue(target)
    .setFilters([
      {
        property: core.properties.isA,
        value: notifications.classes.notification,
      },
    ])
    .setDrive(privateDrive)
    .setPageSize(100)
    .build();
  await collection.waitForReady();

  await markRead(store, await collection.getAllMembers(), upTo);
}

/**
 * The newest Notification per source, newest first. Two devices can both
 * record the same message; the list shows it once, read if either copy is.
 */
export function dedupeBySource(list: Resource[]): Resource[] {
  const bySource = new Map<string, Resource>();

  for (const n of list) {
    const source =
      (n.get(notifications.properties.notificationSource) as
        | string
        | undefined) ?? n.subject;
    const seen = bySource.get(source);

    // Prefer a read copy, so reading one device's copy reads the item.
    if (!seen || (isUnread(seen) && !isUnread(n))) bySource.set(source, n);
  }

  return [...bySource.values()].sort((a, b) => occurredAt(b) - occurredAt(a));
}

export const occurredAt = (n: Resource): number =>
  (n.get(notifications.properties.occurredAt) as number | undefined) ??
  n.getCreatedAt() ??
  0;

/** Several notifications about the same thing, shown as one row. */
export interface NotificationGroup {
  key: string;
  /** Newest first. */
  items: Resource[];
  kind?: string;
  about?: string;
  /** Distinct actors, most recent first. */
  actors: string[];
  unread: boolean;
}

const dayOf = (ms: number) => new Date(ms).toDateString();

/**
 * Groups notifications per thing and kind, so five messages in one chat are
 * one row. Unread and read ones stay apart, and read ones are grouped per
 * day, so history still shows when things happened. Expects the input newest
 * first (as {@link dedupeBySource} returns it) and keeps that order.
 */
export function groupNotifications(list: Resource[]): NotificationGroup[] {
  const groups = new Map<string, NotificationGroup>();

  for (const n of list) {
    const kind = n.get(notifications.properties.notificationKind) as
      | string
      | undefined;
    const about = n.get(dataBrowser.properties.about) as string | undefined;
    const unread = isUnread(n);
    const key = [
      about ?? n.subject,
      kind ?? '',
      unread ? 'unread' : dayOf(occurredAt(n)),
    ].join('|');

    let group = groups.get(key);

    if (!group) {
      group = { key, items: [], kind, about, actors: [], unread };
      groups.set(key, group);
    }

    group.items.push(n);
    const actor = n.get(notifications.properties.actor) as string | undefined;
    if (actor && !group.actors.includes(actor)) group.actors.push(actor);
  }

  return [...groups.values()];
}
