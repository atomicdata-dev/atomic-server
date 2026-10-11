// @wc-ignore-file
import { core, useResources, useStore } from '@tomic/react';
import { useEffect, useMemo, useState } from 'react';
import { searchMessages } from '../../helpers/conversations/messageIndex';
import { useConversations } from '../../helpers/conversations/useConversations';
import { knownPages, scopeKey } from '../../helpers/chatLog';
import { usePrivateDrive } from '../../hooks/usePrivateDrive';
import { useDriveChats } from '../../components/SideBar/AIPanel';
import {
  entryText,
  findChatMatches,
  type ChatCandidate,
  type ChatMatch,
} from './chatMatches';

/** A stable array for `useResources`, which compares by identity. */
function useStableList(subjects: string[]): string[] {
  const key = subjects.join(' ');

  return useMemo(() => (key ? key.split(' ') : []), [key]);
}

/**
 * The signed-in person's DMs and AI chats that match `query`, which the drive
 * search cannot find: DMs are end-to-end encrypted in drives of their own and
 * AI chats live in the private drive.
 *
 * DMs match on member names and on messages this device has decrypted before
 * (see `messageIndex`). AI chats match on messages too, but only pages this
 * session already loaded.
 */
export function useChatMatches(query: string, enabled: boolean): ChatMatch[] {
  const store = useStore();
  const me = store.getAgent()?.subject;
  const { privateDrive } = usePrivateDrive();
  const dms = useStableList(useConversations());
  const aiChats = useStableList(useDriveChats(privateDrive));
  const dmResources = useResources(dms);
  const aiResources = useResources(aiChats);

  const membersOf = (subject: string): string[] => {
    const read = dmResources.get(subject)?.get(core.properties.read);

    return Array.isArray(read)
      ? (read as string[]).filter(member => member !== me)
      : [];
  };

  const memberList = useStableList([
    ...new Set(dms.flatMap(subject => membersOf(subject))),
  ]);
  const memberResources = useResources(memberList);
  const found = useDmTextMatches(query, enabled);

  if (!enabled || query.trim() === '') return [];

  const candidates: ChatCandidate[] = [
    ...dms.map(
      (subject): ChatCandidate => ({
        subject,
        kind: 'dm',
        names: membersOf(subject).map(
          member => memberResources.get(member)?.title ?? member,
        ),
      }),
    ),
    ...aiChats.map(
      (subject): ChatCandidate => ({
        subject,
        kind: 'ai',
        names: [aiResources.get(subject)?.title ?? ''],
        texts: loadedMessageTexts(store, subject),
      }),
    ),
  ];

  return findChatMatches(query, candidates, found);
}

/** Text of the pages of an AI chat this client already knows and has in
 *  memory; nothing is fetched. */
function loadedMessageTexts(
  store: ReturnType<typeof useStore>,
  chat: string,
): string[] {
  return knownPages(store, scopeKey(core.properties.parent, chat)).flatMap(
    page =>
      store
        .getResourceLoading(page)
        .listChatLogEntries()
        .map(({ entry }) => entryText(entry)),
  );
}

const NO_TEXT_MATCHES = new Map<string, string>();

/** Conversations with a decrypted message matching `query`, with that text. */
export function useDmTextMatches(
  query: string,
  enabled: boolean,
): Map<string, string> {
  const store = useStore();
  const [found, setFound] = useState(new Map<string, string>());

  useEffect(() => {
    if (!enabled || query.trim() === '') return;

    let cancelled = false;
    const timer = setTimeout(() => {
      searchMessages(store, query)
        .then(matches => {
          if (!cancelled) {
            setFound(new Map(matches.map(m => [m.conversation, m.text])));
          }
        })
        .catch(() => undefined);
    }, 150);

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [store, query, enabled]);

  return enabled && query.trim() !== '' ? found : NO_TEXT_MATCHES;
}
