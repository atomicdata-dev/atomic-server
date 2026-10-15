import { conversations, type Store } from '@tomic/react';
import { useSyncExternalStore } from 'react';
import { fetchPrivateDriveSubject } from '../privateDrive';
import { fetchMemberOf } from './conversationsEndpoint';
import { membersOf, sameMembers } from './conversationMembers';

const STORAGE_KEY = 'atomic.hidden-conversations';
const EMPTY: string[] = [];

type HiddenByAccount = Record<string, string[]>;

const listeners = new Set<() => void>();

function readAll(): HiddenByAccount {
  try {
    const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '{}');

    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

/** The conversations `agent` left. They stay in the server's list for as long
 *  as the person is a member, so this device remembers not to show them. */
export function getHiddenConversations(agent: string): string[] {
  const hidden = readAll()[agent];

  return Array.isArray(hidden) ? hidden : EMPTY;
}

function writeHidden(agent: string, hidden: string[]) {
  try {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ ...readAll(), [agent]: hidden }),
    );
  } catch {
    // Private mode or full storage: the conversation just comes back.
  }

  listeners.forEach(listener => listener());
}

export function hideConversation(agent: string, subject: string): void {
  const hidden = getHiddenConversations(agent);

  if (!hidden.includes(subject)) writeHidden(agent, [...hidden, subject]);
}

export function unhideConversation(agent: string, subject: string): void {
  const hidden = getHiddenConversations(agent);

  if (hidden.includes(subject)) {
    writeHidden(
      agent,
      hidden.filter(s => s !== subject),
    );
  }
}

/** `subjects` without the ones in `hidden`. */
export function withoutHidden(subjects: string[], hidden: string[]): string[] {
  return hidden.length === 0
    ? subjects
    : subjects.filter(subject => !hidden.includes(subject));
}

/** The hidden conversations of `agent`, kept current across this tab. */
export function useHiddenConversations(agent: string | undefined): string[] {
  return useSyncExternalStore(
    callback => {
      listeners.add(callback);
      window.addEventListener('storage', callback);

      return () => {
        listeners.delete(callback);
        window.removeEventListener('storage', callback);
      };
    },
    // The same array while the stored value is unchanged, or React loops.
    () => (agent ? readCached(agent) : EMPTY),
  );
}

let cachedRaw: string | null | undefined;
let cachedAll: HiddenByAccount = {};

function readCached(agent: string): string[] {
  let raw: string | null = null;

  try {
    raw = localStorage.getItem(STORAGE_KEY);
  } catch {
    // Treated as nothing hidden.
  }

  if (raw !== cachedRaw) {
    cachedRaw = raw;
    cachedAll = readAll();
  }

  const hidden = cachedAll[agent];

  return Array.isArray(hidden) ? hidden : EMPTY;
}

/**
 * Leaves a conversation: drops it from the private drive's list and hides it
 * on this device. Members can't delete it (they only read and append), so it
 * stays on the server for everyone else. Other conversations with the same
 * members (an older duplicate) are left with it, or they would take its place
 * in the list.
 */
export async function leaveConversation(
  store: Store,
  subject: string,
): Promise<void> {
  const agent = store.getAgent();

  const me = agent?.subject;

  if (!agent || !me) return;

  hideConversation(me, subject);

  const privateDriveSubject = await fetchPrivateDriveSubject(store, agent);
  const privateDrive = privateDriveSubject
    ? await store.getResource(privateDriveSubject)
    : undefined;
  const listedValue = privateDrive?.get(conversations.properties.conversations);
  const listed = Array.isArray(listedValue) ? (listedValue as string[]) : [];
  const leaving = [subject, ...(await findTwins(store, subject, listed))];

  leaving.forEach(twin => hideConversation(me, twin));

  if (privateDrive && listed.some(s => leaving.includes(s))) {
    await privateDrive.set(
      conversations.properties.conversations,
      listed.filter(s => !leaving.includes(s)),
    );
    await privateDrive.save();
  }
}

/** The other conversations with the same members as `subject`. */
async function findTwins(
  store: Store,
  subject: string,
  listed: string[],
): Promise<string[]> {
  try {
    const candidates = [
      ...new Set([...listed, ...(await fetchMemberOf(store))]),
    ].filter(candidate => candidate !== subject);
    const members = membersOf(await store.getResource(subject));

    if (!members) return [];

    const twins: string[] = [];

    for (const candidate of candidates) {
      const resource = await store.getResource(candidate);
      const theirs = resource.error ? undefined : membersOf(resource);

      if (theirs && sameMembers(theirs, members)) twins.push(candidate);
    }

    return twins;
  } catch {
    // Finding twins is a courtesy; leaving the one asked for still works.
    return [];
  }
}
