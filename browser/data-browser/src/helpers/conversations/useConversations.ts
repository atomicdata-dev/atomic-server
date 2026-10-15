import {
  conversations,
  useResources,
  useStore,
  type Store,
} from '@tomic/react';
import { useEffect, useMemo, useState } from 'react';
import { useSettings } from '../AppSettings';
import { usePrivateDriveList } from '../../hooks/usePrivateDriveList';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';
import { constructOpenURL } from '../navigation';
import { fetchPrivateDriveSubject } from '../privateDrive';
import {
  unhideConversation,
  useHiddenConversations,
  withoutHidden,
} from './hiddenConversations';
import { hasMembers, startConversation } from './conversations';
import { fetchMemberOf } from './conversationsEndpoint';
import { dedupeByMembers } from './conversationMembers';

/** How often the Messages panel asks the server for conversations someone
 *  else started. Nothing pushes them yet; see `planning/notifications.md`. */
const REFRESH_MS = 60_000;

/**
 * The conversations the signed-in agent is in: the ones listed on their
 * private drive (started here, or opened before), and the ones the server
 * finds them in (started by someone else, see `/conversations`).
 */
export function useConversations(): string[] {
  const store = useStore();
  const { agent } = useSettings();
  const [listed] = usePrivateDriveList(conversations.properties.conversations);
  const [fromServer, setFromServer] = useState<string[]>([]);
  const hidden = useHiddenConversations(agent?.subject);

  useEffect(() => {
    if (!agent?.subject) return;

    let cancelled = false;
    const refresh = () =>
      fetchMemberOf(store).then(found => {
        if (!cancelled) setFromServer(found);
      });

    refresh();
    const timer = setInterval(refresh, REFRESH_MS);
    window.addEventListener('focus', refresh);
    window.addEventListener('online', refresh);

    return () => {
      cancelled = true;
      clearInterval(timer);
      window.removeEventListener('focus', refresh);
      window.removeEventListener('online', refresh);
    };
  }, [store, agent]);

  const all = useMemo(
    () => (agent?.subject ? [...new Set([...listed, ...fromServer])] : listed),
    [agent?.subject, listed, fromServer],
  );
  const resources = useResources(all);

  // Two conversations with the same people show as one. Collapsing comes
  // before hiding, so leaving the kept one hides its twins too.
  return withoutHidden(dedupeByMembers(all, resources).subjects, hidden);
}

/**
 * The conversation with exactly `others` (and the signed-in agent): an
 * existing one, or a new one. Either way it ends up listed on the private
 * drive. Reads everything at call time, so a menu item can offer it without
 * loading anything up front.
 */
export async function findOrStartConversation(
  store: Store,
  others: string[],
): Promise<string> {
  const agent = store.getAgent();

  if (!agent?.subject) {
    throw new Error('Sign in to use messages.');
  }

  const members = [agent.subject, ...others.filter(o => o !== agent.subject)];
  const privateDriveSubject = await fetchPrivateDriveSubject(store, agent);
  const privateDrive = privateDriveSubject
    ? await store.getResource(privateDriveSubject)
    : undefined;
  const listedValue = privateDrive?.get(conversations.properties.conversations);
  const listed = Array.isArray(listedValue) ? (listedValue as string[]) : [];
  const found = await fetchMemberOf(store);

  const candidates = await Promise.all(
    [...new Set([...listed, ...found])].map(subject =>
      store.getResource(subject),
    ),
  );
  const existing = candidates.find(
    candidate => !candidate.error && hasMembers(candidate, members),
  );
  const conversation = existing ?? (await startConversation(store, others));

  // Opening it again brings back a conversation that was left.
  unhideConversation(agent.subject, conversation.subject);

  if (privateDrive && !listed.includes(conversation.subject)) {
    privateDrive.push(
      conversations.properties.conversations,
      [conversation.subject],
      true,
    );
    await privateDrive.save();
  }

  return conversation.subject;
}

/** Opens the conversation with exactly `others`, starting it when needed.
 *  `busy` is true while that runs. */
export function useOpenConversation(): {
  openConversation: (others: string[]) => Promise<void>;
  busy: boolean;
} {
  const store = useStore();
  const navigate = useNavigateWithTransition();
  const [busy, setBusy] = useState(false);

  const openConversation = async (others: string[]) => {
    setBusy(true);

    try {
      const subject = await findOrStartConversation(store, others);
      setBusy(false);
      navigate(constructOpenURL(subject));
    } catch (error) {
      // No `finally`: the React Compiler skips components that use it.
      setBusy(false);
      throw error;
    }
  };

  return { openConversation, busy };
}
