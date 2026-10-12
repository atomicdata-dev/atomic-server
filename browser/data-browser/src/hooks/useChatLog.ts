// @wc-ignore-file
import { useEffect, useState } from 'react';
import {
  commits,
  ResourceEvents,
  unknownSubject,
  useCollection,
  useStore,
} from '@tomic/react';
import type { ChatLogEntry } from '@tomic/react';
import {
  mergePages,
  ONLY_CHAT_LOGS,
  parseEntryId,
  rememberPage,
  scopeKey,
} from '../helpers/chatLog';

/**
 * The pages of a chat: the ChatLog resources whose `property` (`parent` for a
 * ChatRoom, `about` for the comments on an item) is `value`. Live through the
 * collection, plus the pages this client made itself, which a collection does
 * not list before the server has answered (or at all, offline).
 */
export function useChatLogPages(
  property: string,
  value: string,
  drive?: string,
  /** Set false to skip the query, for a chat that has no log. */
  enabled = true,
): {
  pages: string[];
  ready: boolean;
  /** Reads the pages again, for example after this client created one. */
  refresh: () => void;
} {
  const store = useStore();
  const scope = scopeKey(property, value);
  const { collection, ready } = useCollection(
    {
      property,
      value: enabled ? value : unknownSubject,
      filters: ONLY_CHAT_LOGS,
      sort_by: commits.properties.createdAt,
      sort_desc: false,
      drive,
    },
    { pageSize: 100, preferServer: true },
  );
  const [state, setState] = useState<{
    scope: string;
    pages: string[];
    loaded: boolean;
  }>({ scope, pages: [], loaded: false });
  const [refreshes, setRefreshes] = useState(0);

  useEffect(() => {
    // `useCollection` swaps its collection one render after the query
    // changed; the old one answers for the previous chat.
    if (!enabled || collection.value !== value) return;
    let cancelled = false;

    const read = async () => {
      await collection.waitForReady();
      const queried: string[] = [];

      try {
        for (let i = 0; i < collection.totalMembers; i++) {
          const member = await collection.getMemberWithIndex(i);

          if (member) queried.push(member);
        }
      } catch {
        // The collection changed under us; its next refresh reads again.
        return;
      }

      queried.forEach(page => rememberPage(store, scope, page));

      if (!cancelled) {
        setState({
          scope,
          pages: mergePages(store, scope, queried),
          loaded: true,
        });
      }
    };

    void read();

    return () => {
      cancelled = true;
    };
  }, [collection, store, scope, value, enabled, refreshes]);

  const current = state.scope === scope;

  return {
    pages: current ? state.pages : [],
    ready: !enabled || (ready && current && state.loaded),
    refresh: () => setRefreshes(n => n + 1),
  };
}

/**
 * A number that changes whenever one of the pages changes: a commit from
 * another tab or agent, or an entry added here. Entries are not properties, so
 * the property hooks do not see them change.
 */
export function useChatLogRevision(pages: string[]): number {
  const store = useStore();
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    const bump = () => setRevision(r => r + 1);
    const off = pages.flatMap(page => [
      store.subscribe(page, bump),
      store.getResourceLoading(page).on(ResourceEvents.LocalChange, bump),
    ]);

    return () => off.forEach(unsubscribe => unsubscribe());
  }, [store, pages]);

  return revision;
}

/** The entry behind an entry id (and its page changing under it), if loaded. */
export function useChatLogEntry(id: string): {
  entry: ChatLogEntry | undefined;
  key: string | undefined;
  page: string | undefined;
} {
  const store = useStore();
  const parsed = parseEntryId(id);
  const page = parsed?.page;
  const revision = useChatLogRevision(page ? [page] : NO_PAGES);
  // Loaded pages are read by revision: an edit replaces the whole value.
  void revision;
  const entry = parsed
    ? store.getResourceLoading(parsed.page).getChatLogEntry(parsed.key)
    : undefined;

  return { entry, key: parsed?.key, page };
}

const NO_PAGES: string[] = [];

/**
 * The entry keys the pages hold, each once: one key on two pages (two peers
 * migrated the same message) is one message.
 */
export function useChatLogKeys(pages: string[]): ReadonlySet<string> {
  const store = useStore();
  const revision = useChatLogRevision(pages);
  const [keys, setKeys] = useState<ReadonlySet<string>>(NO_KEYS);

  useEffect(() => {
    let cancelled = false;

    void Promise.all(pages.map(page => store.getResource(page))).then(
      resources => {
        if (cancelled) return;
        const next = new Set<string>();

        for (const page of resources) {
          if (page.error) continue;

          for (const { key } of page.listChatLogEntries()) next.add(key);
        }

        setKeys(next);
      },
    );

    return () => {
      cancelled = true;
    };
  }, [store, pages, revision]);

  return pages.length === 0 ? NO_KEYS : keys;
}

const NO_KEYS: ReadonlySet<string> = new Set();

/** How many messages the pages hold in all. */
export function useChatLogCount(pages: string[]): number {
  return useChatLogKeys(pages).size;
}
