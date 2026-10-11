import { conversations, type Store } from '@tomic/react';
import { useSyncExternalStore } from 'react';
import { fetchPrivateDriveSubject } from '../privateDrive';

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
 * stays on the server for everyone else.
 */
export async function leaveConversation(
  store: Store,
  subject: string,
): Promise<void> {
  const agent = store.getAgent();

  if (!agent?.subject) return;

  hideConversation(agent.subject, subject);

  const privateDriveSubject = await fetchPrivateDriveSubject(store, agent);

  if (!privateDriveSubject) return;

  const privateDrive = await store.getResource(privateDriveSubject);
  const listed = privateDrive.get(conversations.properties.conversations);

  if (Array.isArray(listed) && listed.includes(subject)) {
    await privateDrive.set(
      conversations.properties.conversations,
      (listed as string[]).filter(s => s !== subject),
    );
    await privateDrive.save();
  }
}
