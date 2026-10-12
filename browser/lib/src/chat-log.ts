import type { LoroDoc } from 'loro-crdt';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import type { JSONValue } from './value.js';

/**
 * Entries of a `ChatLog` page. They live in the root Loro map `entries` of the
 * page's document, next to `properties` and `datatypes`, and are not
 * properties: the server does not materialize, index or search them.
 * See `planning/chat-log.md`.
 */

/** Name of the root Loro map that holds the entries. */
export const CHAT_LOG_ENTRIES = 'entries';

/** The server refuses entries whose `c` is further than this ahead of its clock. */
export const CHAT_LOG_MAX_FUTURE_MS = 10 * 60 * 1000;

/** The value stored under an entry key: a plain Loro map value, replaced whole on edit. */
export interface ChatLogEntry {
  /** Author agent subject. The server only accepts changes from this agent (or a writer). */
  a: string;
  /** Text, markdown. */
  t: string;
  /** createdAt, ms. */
  c: number;
  /**
   * What is replied to: an entry id (`<page subject>#<entry key>`, so it can
   * be found on another page) or the subject of an old `Message` resource.
   */
  r?: string;
  /** Edited-at, ms. */
  e?: number;
  /** Extra kinds, for example `FollowEvent`. */
  k?: JSONValue;
  /** Further fields pass through untouched. */
  [extra: string]: JSONValue | undefined;
}

/** `<createdAt ms, lowercase hex>-<8 random hex>`: keys sort by time. */
export function newChatLogEntryKey(createdAt: number): string {
  const random = new Uint32Array(1);
  globalThis.crypto.getRandomValues(random);

  return `${createdAt.toString(16)}-${random[0].toString(16).padStart(8, '0')}`;
}

/**
 * The entry key of a `Message` resource that was moved into a log:
 * `<createdAt hex>-<first 8 hex chars of SHA-256 of the subject's id>`. The id
 * is what follows the `did:ad:` / `atomic:` scheme, without query or fragment.
 * Mirrors `migrated_entry_key` in `lib/src/chat_log.rs`; a reader uses it to
 * recognise an old resource (a stale cached copy, a straggler from an old
 * client) whose entry already exists.
 */
export function migratedEntryKey(createdAt: number, subject: string): string {
  return `${Math.max(0, Math.trunc(createdAt)).toString(16)}-${migratedKeyHash(subject)}`;
}

/**
 * The part of a {@link migratedEntryKey} after the dash: the first 8 hex chars
 * of the SHA-256 of the old subject's id. It does not depend on the creation
 * time, so something that only holds the old subject (a reply inside an
 * encrypted payload) can find the entry it became.
 */
export function migratedKeyHash(subject: string): string {
  const id = (
    /^(?:did:ad:|atomic:)(?!\/\/)(.*)$/.exec(subject)?.[1] ?? subject
  ).split(/[?#]/)[0];

  return bytesToHex(sha256(utf8ToBytes(id))).slice(0, 8);
}

function clean(entry: ChatLogEntry): ChatLogEntry {
  return Object.fromEntries(
    Object.entries(entry).filter(([, v]) => v !== undefined),
  ) as ChatLogEntry;
}

/** Add or replace the entry under `key`. The caller commits the doc. */
export function putChatLogEntry(
  doc: LoroDoc,
  key: string,
  entry: ChatLogEntry,
): void {
  doc.getMap(CHAT_LOG_ENTRIES).set(key, clean(entry));
}

/** Add `entry` under a fresh key and return the key. */
export function addChatLogEntry(doc: LoroDoc, entry: ChatLogEntry): string {
  const key = newChatLogEntryKey(entry.c);
  putChatLogEntry(doc, key, entry);

  return key;
}

/** Remove the entry under `key`. */
export function removeChatLogEntry(doc: LoroDoc, key: string): void {
  doc.getMap(CHAT_LOG_ENTRIES).delete(key);
}

/** The entry under `key`, if there is one. */
export function getChatLogEntry(
  doc: LoroDoc,
  key: string,
): ChatLogEntry | undefined {
  const value = doc.getMap(CHAT_LOG_ENTRIES).get(key);

  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as unknown as ChatLogEntry)
    : undefined;
}

/** How many entries the page holds. */
export function countChatLogEntries(doc: LoroDoc): number {
  return doc.getMap(CHAT_LOG_ENTRIES).size;
}

/** Every entry, oldest first (keys sort by time). */
export function listChatLogEntries(
  doc: LoroDoc,
): { key: string; entry: ChatLogEntry }[] {
  const map = doc.getMap(CHAT_LOG_ENTRIES).toJSON() as Record<
    string,
    ChatLogEntry
  >;

  return Object.keys(map)
    .sort()
    .map(key => ({ key, entry: map[key] }));
}

/** An entry as the app writes it: author and time default to the current agent and now. */
export interface NewChatLogEntry {
  a?: string;
  t: string;
  c?: number;
  r?: string;
  e?: number;
  k?: JSONValue;
  [extra: string]: JSONValue | undefined;
}
