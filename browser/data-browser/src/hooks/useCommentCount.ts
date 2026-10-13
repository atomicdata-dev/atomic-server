import { useEffect, useState } from 'react';
import {
  commits,
  core,
  dataBrowser,
  useCollection,
  useStore,
} from '@tomic/react';
import { hideMigrated } from '../helpers/chatLog';
import { useChatLogKeys, useChatLogPages } from './useChatLog';
import { useLastSeenComments } from './useLastSeenComments';

// `about` is also used by AI chats; only Messages are comments.
const ONLY_MESSAGES = [
  { property: core.properties.isA, value: dataBrowser.classes.message },
];

/**
 * Live number of comments on a resource (Messages whose `about` points at it,
 * and entries in the ChatLog pages whose `about` points at it) plus whether
 * some of them are unseen on this device. Comments are client-signed commits,
 * so drive sync keeps the collection membership up to date without refetching.
 */
export function useCommentCount(subject: string): {
  count: number;
  hasUnseen: boolean;
} {
  // The page size must cover the whole thread: `applyResourceChange` can only
  // recognize an already-counted member if it's in a cached page — a sync
  // echo for a member outside the page would be double-counted as new.
  const { collection, ready } = useCollection(
    {
      property: dataBrowser.properties.about,
      value: subject,
      filters: ONLY_MESSAGES,
      sort_by: commits.properties.createdAt,
    },
    { pageSize: 100 },
  );
  const { pages } = useChatLogPages(dataBrowser.properties.about, subject);
  const keys = useChatLogKeys(pages);
  const store = useStore();
  const [lastSeen] = useLastSeenComments(subject);
  // Old Messages that already have their entry are stale copies: the reader
  // hides them, so they are not counted either.
  const [stale, setStale] = useState(0);

  useEffect(() => {
    if (!ready || keys.size === 0) return;

    let cancelled = false;

    void (async () => {
      const old = [];

      for (let i = 0; i < collection.totalMembers; i++) {
        const id = await collection.getMemberWithIndex(i);

        if (id) {
          old.push({
            id,
            at: (await store.getResource(id)).getCreatedAt() ?? 0,
          });
        }
      }

      if (!cancelled) setStale(hideMigrated(old, keys).hidden);
    })().catch(() => undefined);

    return () => {
      cancelled = true;
    };
  }, [collection, ready, keys, store]);

  const count =
    (ready ? collection.totalMembers : 0) -
    (keys.size > 0 ? stale : 0) +
    keys.size;
  const hasUnseen = count > 0 && (lastSeen === undefined || count > lastSeen);

  return { count, hasUnseen };
}
