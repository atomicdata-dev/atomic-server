// @wc-ignore-file
// Chat messages as ChatLog entries (planning/chat-log.md): which page a new
// message goes to, how entries are addressed, and how old Message resources
// and entries are merged into one list. The merge and the page choice are
// plain functions so they can be tested as data.
import {
  CollectionBuilder,
  commits,
  core,
  dataBrowser,
  type Resource,
  type Store,
} from '@tomic/react';
import { migratedEntryKey, type ChatLogEntry } from '@tomic/react';

/** The `drive` stamp of a resource. */
const DRIVE_PROP = 'https://atomicdata.dev/properties/drive';

/** A page holds at most this many entries; the next message starts a new page. */
export const CHAT_LOG_CAPACITY = 256;

/** `about` is also used by AI chats, so ask for the class too. */
export const ONLY_CHAT_LOGS = [
  { property: core.properties.isA, value: dataBrowser.classes.chatLog },
];

const ENTRY_ID = /^(.+)#([0-9a-f]+-[0-9a-f]{8})$/;

/** A message in a log is addressed `<page subject>#<entry key>`. */
export function toEntryId(page: string, key: string): string {
  return `${page}#${key}`;
}

/** Splits an entry id; `undefined` for the subject of an old Message resource. */
export function parseEntryId(
  id: string,
): { page: string; key: string } | undefined {
  const match = ENTRY_ID.exec(id);

  return match ? { page: match[1], key: match[2] } : undefined;
}

export interface Timed {
  /** A Message subject or an entry id. */
  id: string;
  /** createdAt, ms. */
  at: number;
}

export interface ChatWindowInput {
  /** The newest old Message resources that were loaded. */
  old: Timed[];
  /** How many old Message resources there are in all. */
  oldTotal: number;
  /** The entries of the pages that were loaded (newest pages first). */
  log: Timed[];
  /** Pages that were not loaded because the newest ones already fill the window. */
  unloadedPages: number;
  /** How many of the newest messages to show. */
  visible: number;
}

/**
 * The newest `visible` messages of old resources and entries together, oldest
 * first, and how many older ones are not listed. Pages that were not loaded
 * count as one each: at least one entry is in them, so the "show older" row
 * appears; the real number is known once they are loaded.
 */
export function windowChat({
  old,
  oldTotal,
  log,
  unloadedPages,
  visible,
}: ChatWindowInput): { ids: string[]; olderCount: number } {
  const all = [...old, ...log].sort(
    (a, b) => a.at - b.at || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
  );
  const shown = visible >= all.length ? all : all.slice(all.length - visible);

  return {
    ids: shown.map(item => item.id),
    olderCount:
      Math.max(0, oldTotal - old.length) +
      (all.length - shown.length) +
      unloadedPages,
  };
}

/** Whether an entry is a follow event (a system line in a meeting). */
export function isFollowEntry(entry: Pick<ChatLogEntry, 'k'> | undefined) {
  const kinds = entry?.k;

  return Array.isArray(kinds)
    ? kinds.includes(dataBrowser.classes.followEvent)
    : kinds === dataBrowser.classes.followEvent;
}

/**
 * Old Message resources that are not in a log yet. A resource whose entry key
 * (see {@link migratedEntryKey}) exists in a loaded page of its chat has been
 * moved: this is a stale cached copy, or a straggler from a client that has not
 * updated, and the entry is the message that counts.
 */
export function hideMigrated(
  old: Timed[],
  entryKeys: ReadonlySet<string>,
): { shown: Timed[]; hidden: number } {
  const shown = old.filter(
    message => !entryKeys.has(migratedEntryKey(message.at, message.id)),
  );

  return { shown, hidden: old.length - shown.length };
}

export interface PageInfo {
  subject: string;
  entries: number;
  createdAt: number;
}

/** The page a new message goes to: the newest one, if it has room. */
export function pageWithRoom(pages: PageInfo[]): string | undefined {
  const [newest] = [...pages].sort(
    (a, b) => b.createdAt - a.createdAt || (a.subject < b.subject ? 1 : -1),
  );

  return newest && newest.entries < CHAT_LOG_CAPACITY
    ? newest.subject
    : undefined;
}

// --- Pages of one chat, as this client knows them --------------------------

/** Where a chat's pages are found: `parent` of a ChatRoom, `about` of an item. */
export function scopeKey(property: string, value: string): string {
  return `${property}\n${value}`;
}

const known = new WeakMap<Store, Map<string, Set<string>>>();

/**
 * Pages this client created or was told about. A page just created is not in a
 * collection yet (offline, or before the server answered); the next message
 * must still go to it, not to a second page.
 */
export function rememberPage(store: Store, scope: string, page: string) {
  let scopes = known.get(store);

  if (!scopes) known.set(store, (scopes = new Map()));
  let pages = scopes.get(scope);

  if (!pages) scopes.set(scope, (pages = new Set()));
  pages.add(store.normalizeSubject(page));
}

export function knownPages(store: Store, scope: string): string[] {
  return [...(known.get(store)?.get(scope) ?? [])];
}

/** Pages of a chat as a one-off query (a collection of its own). */
export async function queryPages(
  store: Store,
  property: string,
  value: string,
  drive?: string,
): Promise<string[]> {
  const builder = new CollectionBuilder(store)
    .setProperty(property)
    .setValue(value)
    .setFilters(ONLY_CHAT_LOGS)
    .setSortBy(commits.properties.createdAt)
    .setSortDesc(false)
    .setPageSize(100)
    .setPreferServer(true);

  if (drive) builder.setDrive(drive);
  const collection = builder.build();
  await collection.waitForReady();
  const pages: string[] = [];

  for (let i = 0; i < collection.totalMembers; i++) {
    const member = await collection.getMemberWithIndex(i);

    if (member) pages.push(member);
  }

  return pages;
}

/** Every page, oldest first: the ones in a query and the ones this client made. */
export function mergePages(
  store: Store,
  scope: string,
  queried: string[],
): string[] {
  const seen = new Set(queried.map(page => store.normalizeSubject(page)));
  const extra = knownPages(store, scope).filter(page => !seen.has(page));

  return [...queried, ...extra];
}

export interface SendLogMessage {
  /** Rights anchor of the page: the ChatRoom, or the drive's comments folder. */
  parent: string;
  /** Comments: the item the log belongs to. */
  about?: string;
  text: string;
  /** An entry id or the subject of an old Message. */
  replyTo?: string;
  /** `FollowEvent` for a system line of a meeting. */
  kind?: string;
  /** Writes the entry as this author instead of the signed-in agent (the demo's personas). */
  author?: string;
  /** Pages of this chat the client already knows. */
  pages: string[];
  scope: string;
}

const queues = new WeakMap<Store, Map<string, Promise<unknown>>>();

/**
 * Appends a message to the newest page with room, or creates the next page.
 * Sends to one chat run one after the other, so a fast second message does
 * not create a second page next to the first.
 */
export function appendToChatLog(
  store: Store,
  message: SendLogMessage,
): Promise<string> {
  let byScope = queues.get(store);

  if (!byScope) queues.set(store, (byScope = new Map()));
  const previous = byScope.get(message.scope) ?? Promise.resolve();
  const run = previous
    .catch(() => undefined)
    .then(() => append(store, message));
  byScope.set(message.scope, run);

  return run;
}

async function append(
  store: Store,
  { parent, about, text, replyTo, kind, author, pages, scope }: SendLogMessage,
): Promise<string> {
  const candidates = mergePages(store, scope, pages);
  const infos: PageInfo[] = [];

  // Only the newest few matter: older pages are full.
  for (const subject of candidates.slice(-3)) {
    const page = await store.getResource(subject);

    if (page.error) continue;

    infos.push({
      subject,
      entries: page.countChatLogEntries(),
      createdAt: page.getCreatedAt() ?? 0,
    });
  }

  const target = pageWithRoom(infos);
  const entry = {
    t: text,
    ...(replyTo && { r: replyTo }),
    ...(kind && { k: kind }),
    ...(author && { a: author }),
  };

  if (target) {
    const page = await store.getResource(target);
    const key = page.addChatLogEntry(entry);

    if (!key) throw new Error('Could not add the message to the chat');
    await page.save();

    return toEntryId(page.subject, key);
  }

  const page = await store.newResource({
    parent,
    isA: dataBrowser.classes.chatLog,
    propVals: about ? { [dataBrowser.properties.about]: about } : {},
  });
  rememberPage(store, scope, page.subject);
  const key = page.addChatLogEntry(entry);

  if (!key) throw new Error('Could not add the message to the chat');
  await page.save();
  store.notifyResourceManuallyCreated(page);

  return toEntryId(page.subject, key);
}

// --- Reading and changing one entry ----------------------------------------

/** The entry behind an entry id, if its page is loaded. */
export function readLogEntry(
  store: Store,
  id: string,
): { entry: ChatLogEntry; page: Resource; key: string } | undefined {
  const parsed = parseEntryId(id);

  if (!parsed) return undefined;
  const page = store.getResourceLoading(parsed.page);
  const entry = page.getChatLogEntry(parsed.key);

  return entry ? { entry, page, key: parsed.key } : undefined;
}

/** Replaces the text of an entry. Only its author may. */
export async function editLogEntry(store: Store, id: string, text: string) {
  const found = readLogEntry(store, id);

  if (!found) throw new Error('This message is not loaded');
  found.page.putChatLogEntry(found.key, {
    ...found.entry,
    t: text,
    e: Date.now(),
  });
  await found.page.save();
}

/** Removes an entry. Only its author may. */
export async function deleteLogEntry(store: Store, id: string) {
  const found = readLogEntry(store, id);

  if (!found) throw new Error('This message is not loaded');
  found.page.removeChatLogEntry(found.key);
  await found.page.save();
}

export interface SendEntryOptions {
  /** The chat the message goes to; `about` makes it a comment on that item. */
  parent: string;
  text: string;
  about?: string;
  replyTo?: string;
  /** Marks a system line, for example a follow event in a meeting. */
  kind?: string;
  /** See {@link SendLogMessage.author}. */
  author?: string;
}

/**
 * Writes a message as an entry of the chat's log, without a hook around it:
 * for the code that posts messages on its own (meeting and follow events).
 * Finds the chat's pages itself.
 */
export async function sendLogEntry(
  store: Store,
  { parent, text, about, replyTo, kind, author }: SendEntryOptions,
): Promise<string> {
  const property = about
    ? dataBrowser.properties.about
    : core.properties.parent;
  const value = about ?? parent;
  const scope = scopeKey(property, value);
  // Pages this client made or saw are remembered; ask the server only for the
  // first message of a chat.
  let pages = knownPages(store, scope);

  if (pages.length === 0) {
    const chat = await store.getResource(parent);
    const drive = chat.get(DRIVE_PROP);
    pages = await queryPages(
      store,
      property,
      value,
      typeof drive === 'string' ? drive : undefined,
    );
  }

  return appendToChatLog(store, {
    parent,
    about,
    text,
    replyTo,
    kind,
    author,
    pages,
    scope,
  });
}
