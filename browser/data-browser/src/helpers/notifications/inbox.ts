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
// the message); the list shows one item per source, with read receipts on the personal drive.
import {
  core,
  Datatype,
  dataBrowser,
  notifications,
  CollectionBuilder,
  toLegacyScheme,
  RequestCancelledError,
  type Resource,
  type Store,
} from '@tomic/react';
import { getOrCreateDriveLocation } from '../standardLocations';
import { notificationSourceId } from './identity';

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

function notificationSession(store: Store): () => void {
  const generation = store.getIdentityGeneration();

  return () => {
    if (store.getIdentityGeneration() !== generation)
      throw new RequestCancelledError('Notification session changed');
  };
}

/** The Inbox in the private drive, created on first use. */
export async function getOrCreateInbox(
  store: Store,
  privateDrive: string,
): Promise<string> {
  return getOrCreateDriveLocation(
    store,
    privateDrive,
    notifications.properties.inbox,
    { isA: notifications.classes.inbox, name: 'Inbox' },
  );
}

/** Known copies of this source in the private drive. Partial discovery is safe:
 * concurrent/offline creation can already produce copies, and logical identity
 * plus the read ledger reconciles them. Absence never means deleting data. */
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
  const checkSession = notificationSession(store);
  const inbox = await getOrCreateInbox(store, privateDrive);
  checkSession();

  const source = notificationSourceId(record.source);
  const copies = await Promise.all(
    [...new Set([source, toLegacyScheme(source)])].map(id =>
      findNotificationsFor(store, privateDrive, id),
    ),
  );
  checkSession();
  const existing = copies.flat()[0];

  if (existing) {
    if (record.read) await markRead(store, [existing]);

    return existing;
  }

  const propVals: Record<string, string | number> = {
    [core.properties.name]: record.title,
    [core.properties.description]: record.body,
    [dataBrowser.properties.about]: record.about,
    [notifications.properties.notificationSource]: source,
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
  checkSession();
  await resource.save();
  checkSession();
  store.notifyResourceManuallyCreated(resource);
  if (record.read) await writeReadReceipts(store, [resource], true);

  return resource.subject;
}

/** Root map keyed by canonical source event. Lives on the personal drive, whose
 * identity already survives non-extractable signing sessions. Independent event
 * keys merge without replacing one another; explicit unread is a stored value,
 * so a late duplicate cannot resurrect an old read receipt. */
export const RECEIPT_MAP = 'notificationReadState';
export type NotificationReceipts = Record<
  string,
  { read: boolean; at: number }
>;

export function readReceipts(home?: Resource): NotificationReceipts {
  return (home?.getLoroDoc()?.getMap(RECEIPT_MAP).toJSON() ??
    {}) as NotificationReceipts;
}

export const isUnread = (
  notification: Resource,
  receipts?: NotificationReceipts,
): boolean => {
  const source = notification.get(notifications.properties.notificationSource);
  const receipt =
    typeof source === 'string'
      ? receipts?.[notificationSourceId(source)]
      : undefined;

  return receipt
    ? !receipt.read
    : notification.get(notifications.properties.readAt) === undefined;
};

async function writeReadReceipts(
  store: Store,
  items: Resource[],
  read: boolean,
): Promise<void> {
  if (!items.length || !store.getAgent()?.subject) return;
  const checkSession = notificationSession(store);
  const home = await store.getResource(await store.privateDriveSubject());
  checkSession();
  if (home.error) throw home.error;
  const map = home.getLoroDoc()?.getMap(RECEIPT_MAP);
  if (!map) throw new Error('Notification history is not ready');
  let changed = false;

  for (const item of items) {
    const source = item.get(notifications.properties.notificationSource);
    if (typeof source !== 'string') continue;
    const id = notificationSourceId(source);
    const previous = map.get(id) as { read?: boolean } | undefined;
    if (previous?.read === read) continue;
    map.set(id, { read, at: Date.now() });
    changed = true;
  }

  if (changed) {
    home.markDirty();
    await home.save();
  }
}

/** Explicit unread is causal state shared by every copy of an event. */
export async function markUnread(
  store: Store,
  subjects: string[],
): Promise<void> {
  return setReadState(store, subjects, false);
}

/** Mark notifications read up to the instant the user saw the conversation. */
export async function markRead(
  store: Store,
  subjects: string[],
  upTo = Number.POSITIVE_INFINITY,
): Promise<void> {
  return setReadState(store, subjects, true, upTo);
}

async function setReadState(
  store: Store,
  subjects: string[],
  read: boolean,
  upTo = Number.POSITIVE_INFINITY,
): Promise<void> {
  const checkSession = notificationSession(store);
  const now = Date.now();
  const items = (
    await Promise.all(subjects.map(subject => store.getResource(subject)))
  ).filter(item => !item.error && occurredAt(item) <= upTo);
  checkSession();
  await writeReadReceipts(store, items, read);
  await Promise.all(
    items.map(async item => {
      checkSession();
      if (isUnread(item) !== read) return;
      await item.set(
        notifications.properties.readAt,
        read ? now : undefined,
        false,
      );
      checkSession();
      await item.save();
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
  const checkSession = notificationSession(store);
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
  const subjects = await collection.getAllMembers();
  checkSession();
  await markRead(store, subjects, upTo);
}

/**
 * The newest Notification per source, newest first. Two devices can both
 * record the same message; the list shows it once, read if either copy is.
 */
export function dedupeBySource(
  list: Resource[],
  receipts?: NotificationReceipts,
): Resource[] {
  const bySource = new Map<string, Resource>();

  for (const n of list) {
    const source = notificationSourceId(
      (n.get(notifications.properties.notificationSource) as
        | string
        | undefined) ?? n.subject,
    );
    const seen = bySource.get(source);

    // Prefer a read copy, so reading one device's copy reads the item.
    if (!seen || (isUnread(seen, receipts) && !isUnread(n, receipts)))
      bySource.set(source, n);
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
export function groupNotifications(
  list: Resource[],
  receipts?: NotificationReceipts,
): NotificationGroup[] {
  const groups = new Map<string, NotificationGroup>();

  for (const n of list) {
    const kind = n.get(notifications.properties.notificationKind) as
      | string
      | undefined;
    const about = n.get(dataBrowser.properties.about) as string | undefined;
    const unread = isUnread(n, receipts);
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
