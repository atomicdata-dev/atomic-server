import {
  type Resource,
  type Ai,
  type Store,
  ai,
  core,
  dataBrowser,
  newChatLogEntryKey,
  type ChatLogEntry,
} from '@tomic/react';
import type {
  FileUIPart,
  ReasoningUIPart,
  SourceUrlUIPart,
  TextUIPart,
  ToolUIPart,
} from 'ai';
import { newContextItem } from '@components/AI/AISidebarContext';
import {
  type AIAtomicResourceMessageContext,
  type AIMCPResourceMessageContext,
  type AIMessageContext,
  type AtomicUIMessage,
} from './types';
import { restoreToolPart } from './toolHistory';
import { userTiming } from '@helpers/userTiming';
import {
  hideMigrated,
  knownPages,
  mergePages,
  pageWithRoom,
  parseEntryId,
  queryPages,
  rememberPage,
  scopeKey,
  toEntryId,
  type PageInfo,
  type Timed,
} from '@helpers/chatLog';
import { entryToMessage, messageToEntry } from './aiChatEntries';

const TAG_TO_ROLE_MAPPING = {
  'https://atomicdata.dev/01jtjxtsa9syxmfca2zx5gcnmj/tag/user': 'user',
  'https://atomicdata.dev/01jtjxtsa9syxmfca2zx5gcnmj/tag/assistant':
    'assistant',
  'https://atomicdata.dev/01jtjxtsa9syxmfca2zx5gcnmj/tag/system': 'system',
  'https://atomicdata.dev/01jtjxtsa9syxmfca2zx5gcnmj/tag/tool': 'tool',
  'https://atomicdata.dev/01jtjxtsa9syxmfca2zx5gcnmj/tag/error': 'error',
  'https://atomicdata.dev/01jtjxtsa9syxmfca2zx5gcnmj/tag/summary': 'summary',
} as const;

/**
 * Where a saved message lives. Messages are entries of the chat's `ChatLog`
 * pages (planning/chat-log.md); a `resource` is an old `ai-message` that has
 * not been migrated yet (a cache of a hosted drive, until its server has).
 */
export type AiMessageRef =
  | { kind: 'entry'; page: string; key: string }
  | { kind: 'resource'; resource: Resource<Ai.AiMessage> };

/** Where a chat's pages are found. */
const scopeOf = (chat: Resource) =>
  scopeKey(core.properties.parent, chat.subject);

interface ChatState {
  /** Refs of messages written in this session, by UI message id. */
  refs: Map<string, AiMessageRef>;
  /** The newest `c` this client knows of: a new entry goes after it. */
  lastC: number;
  /** Pages were asked from the server once. */
  queried: boolean;
}

const chatStates = new WeakMap<Resource, ChatState>();

const stateOf = (chat: Resource): ChatState => {
  let state = chatStates.get(chat);

  if (!state) {
    chatStates.set(
      chat,
      (state = { refs: new Map(), lastC: 0, queried: false }),
    );
  }

  return state;
};

/** The pages of a chat, oldest first: the ones the server lists and the ones made here. */
async function pagesOf(chat: Resource, store: Store): Promise<string[]> {
  const state = stateOf(chat);
  const scope = scopeOf(chat);

  // A draft chat has no server side yet, so nothing to ask.
  if (!state.queried && !chat.new) {
    state.queried = true;

    try {
      const drive = chat.get('https://atomicdata.dev/properties/drive');
      const queried = await queryPages(
        store,
        core.properties.parent,
        chat.subject,
        typeof drive === 'string' ? drive : undefined,
      );
      queried.forEach(page => rememberPage(store, scope, page));
    } catch (error) {
      // Offline: the pages this client knows are the best there is.
      console.warn('Could not list the pages of the chat', error);
      state.queried = false;
    }
  }

  return mergePages(store, scope, knownPages(store, scope));
}

/** The newest page that has room, or a new one (not saved yet). */
async function pageForNewEntry(
  chat: Resource,
  store: Store,
): Promise<{ page: Resource; created: boolean }> {
  const infos: PageInfo[] = [];

  // Only the newest few matter: older pages are full.
  for (const subject of (await pagesOf(chat, store)).slice(-3)) {
    const page = await store.getResource(subject);

    if (page.error) continue;

    infos.push({
      subject,
      entries: page.countChatLogEntries(),
      createdAt: page.getCreatedAt() ?? 0,
    });
  }

  const target = pageWithRoom(infos);

  if (target) return { page: await store.getResource(target), created: false };

  const page = await store.newResource({
    parent: chat.subject,
    isA: dataBrowser.classes.chatLog,
  });
  rememberPage(store, scopeOf(chat), page.subject);

  return { page, created: true };
}

// Serialize writes per chat so an older partial reply cannot overwrite its
// completed version, and concurrent saves cannot append duplicate messages.
const chatWrites = new WeakMap<Resource, Promise<unknown>>();

/**
 * Run `work` on the chat's write queue, after everything already queued.
 *
 * For work that has to be ordered against the message writes but is not one
 * itself — pushing a draft chat to the server, which decides for every write
 * after it whether that write is persisted or left local. Run beside the
 * queue rather than on it, that decision is read by writes already in
 * flight, and whichever of them lands in the gap is never sent at all.
 */
export const queueChatWrite = <T>(
  chatResource: Resource,
  work: () => Promise<T>,
): Promise<T> => {
  const previous = chatWrites.get(chatResource) ?? Promise.resolve();
  const next = previous.catch(() => {}).then(work);
  chatWrites.set(chatResource, next);

  return next;
};

/** Sends what a message needs to the server: its page, or its old resources. */
export const persistMessageResourceToServer = async (
  ref: AiMessageRef,
  store: Store,
): Promise<void> => {
  if (ref.kind === 'entry') {
    const page = await store.getResource(ref.page);
    // Always call save(): a draft page has a stashed genesis and no dirty flag
    // of its own, and skipping it leaves it local-only.
    await page.save();
    void store.notifyResourceManuallyCreated(page);

    return;
  }

  const messageResource = ref.resource;

  for (const subject of messageResource.props.parts ?? []) {
    await (await store.getResource(subject)).save();
  }

  await messageResource.save();
};

/**
 * Writes a message as an entry of the chat's log: a new one at the end, or,
 * for a message already written (a checkpoint of a streaming reply, a retry),
 * the same entry again with its key and time kept, so the order does not move.
 * With `persistToServer: false` (a draft chat) the page only changes locally.
 */
export const addMessageToChatResource = async (
  message: AtomicUIMessage,
  chatResource: Resource<Ai.AiChat>,
  store: Store,
  { persistToServer = true }: { persistToServer?: boolean } = {},
): Promise<AiMessageRef> => {
  const snapshot = structuredClone(message);

  return queueChatWrite(chatResource, async () => {
    const state = stateOf(chatResource);
    const author = store.getAgent()?.subject;

    if (!author) throw new Error('Sign in to save this chat');

    const known = state.refs.get(snapshot.id);
    const parsed = known ?? entryRefFromId(snapshot.id);
    let page: Resource | undefined;
    let key: string | undefined;
    let created = false;
    let entry: ChatLogEntry;

    const previous =
      parsed?.kind === 'entry'
        ? await store.getResource(parsed.page).then(p => {
            const found = p.getChatLogEntry(parsed.key);

            if (found) {
              page = p;
              key = parsed.key;
            }

            return found;
          })
        : undefined;

    if (previous && page && key) {
      entry = messageToEntry(snapshot, previous.a, previous.c);
    } else {
      const c = Math.max(Date.now(), state.lastC + 1);
      ({ page, created } = await pageForNewEntry(chatResource, store));
      key = newChatLogEntryKey(c);
      entry = messageToEntry(snapshot, author, c);
    }

    state.lastC = Math.max(state.lastC, entry.c);
    page.putChatLogEntry(key, entry);

    if (persistToServer) {
      await page.save();

      if (created) void store.notifyResourceManuallyCreated(page);
    }

    const ref: AiMessageRef = { kind: 'entry', page: page.subject, key };
    state.refs.set(snapshot.id, ref);

    return ref;
  });
};

function entryRefFromId(id: string): AiMessageRef | undefined {
  const parsed = parseEntryId(id);

  return parsed
    ? { kind: 'entry', page: parsed.page, key: parsed.key }
    : undefined;
}

/** Removes messages from the chat: entries from their pages, old resources destroyed. */
async function removeRefs(
  refs: AiMessageRef[],
  chatResource: Resource<Ai.AiChat>,
  store: Store,
  persist: boolean,
): Promise<void> {
  const state = stateOf(chatResource);
  const byPage = new Map<string, string[]>();
  const resources: Resource[] = [];

  for (const ref of refs) {
    if (ref.kind === 'entry') {
      byPage.set(ref.page, [...(byPage.get(ref.page) ?? []), ref.key]);
    } else {
      resources.push(ref.resource);
    }
  }

  for (const [pageSubject, keys] of byPage) {
    const page = await store.getResource(pageSubject);

    for (const key of keys) page.removeChatLogEntry(key);

    if (persist) await page.save();
  }

  if (resources.length > 0) {
    const gone = new Set(resources.map(r => r.subject));
    await chatResource.set(
      ai.properties.messages,
      chatResource.props.messages?.filter(subject => !gone.has(subject)),
    );

    if (persist) await chatResource.save();

    for (const resource of resources) {
      try {
        await resource.destroy();
      } catch (error) {
        console.error('Error removing message:', error);
      }
    }
  }

  for (const [id, known] of state.refs) {
    if (
      refs.some(
        ref =>
          ref.kind === known.kind &&
          (ref.kind === 'entry' && known.kind === 'entry'
            ? ref.page === known.page && ref.key === known.key
            : ref === known),
      )
    ) {
      state.refs.delete(id);
    }
  }
}

export const removeMessageFromChatResource = (
  ref: AiMessageRef,
  chatResource: Resource<Ai.AiChat>,
  store: Store,
  { persist = true }: { persist?: boolean } = {},
): Promise<void> =>
  queueChatWrite(chatResource, () =>
    removeRefs([ref], chatResource, store, persist),
  );

export const removeFollowingMessagesFromChatResource = async (
  message: AtomicUIMessage,
  messages: AtomicUIMessage[],
  messageToRefMap: Map<AtomicUIMessage, AiMessageRef>,
  chatResource: Resource<Ai.AiChat>,
  store: Store,
  { persist = true }: { persist?: boolean } = {},
): Promise<AtomicUIMessage[]> => {
  const messageIndex = messages.findIndex(x => x.id === message.id);

  if (messageIndex === -1) {
    throw new Error(`Message not found: ${message.id}`);
  }

  const refs: AiMessageRef[] = [];

  for (const m of messages.slice(messageIndex + 1)) {
    const ref = messageToRefMap.get(m);

    if (!ref) throw new Error(`Message not saved: ${m.id}`);

    refs.push(ref);
  }

  await queueChatWrite(chatResource, () =>
    removeRefs(refs, chatResource, store, persist),
  );

  return messages.slice(0, messageIndex + 1);
};

const compareKeys = (a: AiMessageRef, b: AiMessageRef) =>
  a.kind === 'entry' && b.kind === 'entry' && a.key !== b.key
    ? a.key < b.key
      ? -1
      : 1
    : 0;

interface Placed {
  message: AtomicUIMessage;
  ref: AiMessageRef;
  at: number;
}

/** Two lists that are each in order, merged by time; `first` goes first on a tie. */
export function mergeByTime<T extends { at: number }>(
  first: T[],
  second: T[],
): T[] {
  const merged: T[] = [];
  let i = 0;
  let j = 0;

  while (i < first.length || j < second.length) {
    if (
      j >= second.length ||
      (i < first.length && first[i].at <= second[j].at)
    ) {
      merged.push(first[i++]);
    } else {
      merged.push(second[j++]);
    }
  }

  return merged;
}

/**
 * Everything a chat holds, oldest first: the entries of its pages and the old
 * `ai-message` resources that are not in a page yet. An old message whose
 * deterministic entry key exists in a page has been migrated; the entry counts
 * and the stale copy is not shown.
 */
export const loadChatMessages = async (
  chatResource: Resource<Ai.AiChat>,
  store: Store,
): Promise<Map<AtomicUIMessage, AiMessageRef>> => {
  const timing = userTiming('chat:load');
  const state = stateOf(chatResource);
  const pages = await pagesOf(chatResource, store);
  const seen = new Set<string>();
  const logged: Placed[] = [];

  for (const subject of pages) {
    const page = await store.getResource(subject);

    if (page.error) continue;

    for (const { key, entry } of page.listChatLogEntries()) {
      // One key on two pages (two peers migrated the same message) is one message.
      if (seen.has(key)) continue;

      seen.add(key);
      const id = toEntryId(page.subject, key);
      const message = entryToMessage(id, entry);

      if (message) {
        logged.push({
          message,
          ref: { kind: 'entry', page: page.subject, key },
          at: entry.c,
        });
      }

      state.lastC = Math.max(state.lastC, entry.c);
    }
  }

  logged.sort((a, b) => a.at - b.at || compareKeys(a.ref, b.ref));
  timing.step('entries');

  const oldSubjects = chatResource.props.messages ?? [];
  const placed: Placed[] = [];

  if (oldSubjects.length > 0) {
    const resources = await store.getResources(oldSubjects);
    const timed: Timed[] = oldSubjects.map((id, i) => ({
      id,
      at: resources[i].getCreatedAt() ?? 0,
    }));
    const shown = new Set(hideMigrated(timed, seen).shown.map(t => t.id));
    const atOf = new Map(timed.map(t => [t.id, t.at]));
    const old = await messageResourcesToDisplayMessages(
      oldSubjects.filter(subject => shown.has(subject)),
      store,
    );

    for (const [message, resource] of old) {
      placed.push({
        message,
        ref: { kind: 'resource', resource },
        at: atOf.get(resource.subject) ?? 0,
      });
    }
  }

  timing.step('convert');

  return new Map(
    mergeByTime(placed, logged).map(({ message, ref }) => [message, ref]),
  );
};

/**
 * Loads a chat's messages in two network rounds, however long the chat is:
 * every message resource at once, then every part and context item of every
 * message at once. Loading them message by message made opening a chat cost
 * one round trip per message, which is why long chats felt slow to open.
 */
export const messageResourcesToDisplayMessages = async (
  subjects: string[],
  store: Store,
): Promise<Map<AtomicUIMessage, Resource<Ai.AiMessage>>> => {
  const timing = userTiming('chat:load');
  const resources = await store.getResources<Ai.AiMessage>(subjects);
  timing.step('messages');
  const loaded = resources.filter(r => !r.error);
  const partSubjects = loaded.flatMap(r => r.props.parts ?? []);
  const contextSubjects = loaded.flatMap(r => r.props.providedContext ?? []);
  const [parts, contexts] = await Promise.all([
    store.getResources(partSubjects),
    Promise.allSettled(
      contextSubjects.map(s => resourceToAIMessageContext(s, store)),
    ),
  ]);
  timing.step('parts');
  const partBySubject = new Map(partSubjects.map((s, i) => [s, parts[i]]));
  const contextBySubject = new Map(
    contextSubjects.map((s, i) => [s, contexts[i]]),
  );

  const messages = new Map<AtomicUIMessage, Resource<Ai.AiMessage>>();

  for (const resource of resources) {
    if (resource.error) {
      console.error(resource.error);
      messages.set(
        {
          id: resource.subject,
          role: 'assistant',
          parts: [],
          metadata: {
            error: resource.error.message,
          },
        } satisfies AtomicUIMessage,
        resource,
      );
      continue;
    }

    const role = tagToRole(resource.props.role);

    const partResources = (resource.props.parts ?? []).map(
      s => partBySubject.get(s)!,
    );

    let message: AtomicUIMessage | undefined;

    if (role === 'user') {
      message = {
        id: resource.subject,
        role,
        parts: partResources.map(r => {
          if (resourceIsFilePart(r)) {
            return toFilePart(r);
          }

          if (resourceIsTextPart(r)) {
            return toTextPart(r);
          }

          throw new Error(
            `Content with class ${r.getClasses()} not supported on role: user`,
          );
        }),
      };

      if (resource.props.providedContext) {
        const context = resource.props.providedContext
          .map(c => contextBySubject.get(c))
          .filter(
            (c): c is PromiseFulfilledResult<AIMessageContext> =>
              c?.status === 'fulfilled',
          )
          .map(c => c.value);

        message.metadata = {
          ...(message.metadata ?? {}),
          userContext: context,
        };
      }

      if (resource.props.serverProvidedContext) {
        message.metadata = {
          ...(message.metadata ?? {}),
          serverContext: resource.props.serverProvidedContext,
        };
      }
    }

    if (role === 'assistant') {
      message = {
        id: resource.subject,
        role,
        parts: partResources.map(r => {
          if (resourceIsReasoningPart(r)) {
            return toReasoningPart(r);
          }

          if (resourceIsTextPart(r)) {
            return toTextPart(r);
          }

          if (resourceIsToolCallPart(r)) {
            return toToolCallPart(r);
          }

          if (resourceIsSourceUrlPart(r)) {
            return toSourceUrlPart(r);
          }

          if (resourceIsFilePart(r)) {
            return toFilePart(r);
          }

          throw new Error(
            `Content with class ${r.getClasses()} not supported on role: assistant`,
          );
        }),
      };
    }

    if (role === 'system') {
      const contentResource = partResources[0];

      if (!resourceIsTextPart(contentResource)) {
        throw new Error(
          `Part with class ${contentResource.getClasses()} not supported on role: system`,
        );
      }

      message = {
        id: resource.subject,
        role,
        parts: [toTextPart(contentResource)],
      };
    }

    if (role === 'summary') {
      const contentResource = partResources[0];

      if (!resourceIsTextPart(contentResource)) {
        throw new Error(
          `Part with class ${contentResource.getClasses()} not supported on role: summary`,
        );
      }

      message = {
        id: resource.subject,
        role: 'user',
        parts: [toTextPart(contentResource)],
        metadata: { isSummary: true },
      };
    }

    if (message) {
      if (role === 'assistant' && resource.get(core.properties.description)) {
        message.metadata = {
          ...message.metadata,
          error: resource.get(core.properties.description),
        };
      }

      messages.set(message, resource);
    }
  }

  timing.step('convert');

  return messages;
};

const resourceToAIMessageContext = async (
  subject: string,
  store: Store,
): Promise<AIMessageContext> => {
  const resource = await store.getResource(subject);

  if (resource.error) {
    throw resource.error;
  }

  if (resource.hasClasses(ai.classes.mcpResource)) {
    return newContextItem<AIMCPResourceMessageContext>({
      type: 'mcp-resource',
      name: resource.props.name,
      uri: resource.props.mcpUri,
      serverId: resource.props.mcpServerId,
      mimetype: resource.props.mimetype,
    });
  }

  return newContextItem<AIAtomicResourceMessageContext>({
    type: 'atomic-resource',
    subject: resource.subject,
  });
};

const tagToRole = (subject: string) => {
  const tag = TAG_TO_ROLE_MAPPING[subject as keyof typeof TAG_TO_ROLE_MAPPING];

  if (!tag) {
    throw new Error(`Unknown message role: ${subject}`);
  }

  return tag;
};

const toFilePart = (resource: Resource<Ai.FilePart>): FileUIPart => {
  return {
    type: 'file',
    url: resource.props.data,
    filename: resource.props.filename,
    mediaType: resource.props.mimetype!,
  };
};

const toTextPart = (resource: Resource<Ai.TextPart>): TextUIPart => ({
  type: 'text',
  text: resource.props.description,
});

const toReasoningPart = (
  resource: Resource<Ai.ReasoningPart>,
): ReasoningUIPart => ({
  type: 'reasoning',
  text: resource.props.description,
});

const toToolCallPart = (resource: Resource<Ai.ToolCallPart>): ToolUIPart =>
  restoreToolPart(resource.props);

const toSourceUrlPart = (
  resource: Resource<Ai.SourceUrlPart>,
): SourceUrlUIPart => ({
  type: 'source-url',
  sourceId: crypto.randomUUID(), // Do we need real IDs?
  url: resource.props.url,
  title: resource.props.name,
});

const resourceIsFilePart = (
  resource: Resource,
): resource is Resource<Ai.FilePart> =>
  resource.hasClasses(ai.classes.filePart);

const resourceIsTextPart = (
  resource: Resource,
): resource is Resource<Ai.TextPart> =>
  resource.hasClasses(ai.classes.textPart);

const resourceIsReasoningPart = (
  resource: Resource,
): resource is Resource<Ai.ReasoningPart> =>
  resource.hasClasses(ai.classes.reasoningPart);

const resourceIsToolCallPart = (
  resource: Resource,
): resource is Resource<Ai.ToolCallPart> =>
  resource.hasClasses(ai.classes.toolCallPart);

const resourceIsSourceUrlPart = (
  resource: Resource,
): resource is Resource<Ai.SourceUrlPart> =>
  resource.hasClasses(ai.classes.sourceUrlPart);
