import {
  core,
  dataBrowser,
  type Resource,
  type Store,
  type Ai,
} from '@tomic/react';
import type { AtomicUIMessage } from './types';
import type { ChatTitle } from './useGenerativeData';
import {
  addMessageToChatResource,
  persistMessageResourceToServer,
  queueChatWrite,
  type AiMessageRef,
} from './chatConversionUtils';
import { DEFAULT_AICHAT_NAME } from '@components/AI/aiContstants';

export type DraftChatResource = Resource<Ai.AiChat>;
export type TitlePromise = Promise<ChatTitle | undefined>;

export type PersistSidebarMessageArgs = {
  message: AtomicUIMessage;
  newMessages: AtomicUIMessage[];
  store: Store;
  getOrCreateDraftChatResource: () => Promise<DraftChatResource | undefined>;
  isChatSavedRef: React.MutableRefObject<boolean>;
  titlePromiseRef: React.MutableRefObject<TitlePromise | undefined>;
  setMessageToResourceMap: React.Dispatch<
    React.SetStateAction<Map<AtomicUIMessage, AiMessageRef>>
  >;
  messageToResourceMapRef: React.MutableRefObject<
    Map<AtomicUIMessage, AiMessageRef>
  >;
  setIsChatSaved: React.Dispatch<React.SetStateAction<boolean>>;
  shouldGenerateTitles: boolean;
  generateTitle: (messages: AtomicUIMessage[]) => TitlePromise;
};

/**
 * When a sidebar chat stops being a draft and becomes a resource.
 *
 * On the user's message, not on the reply that follows it. The draft exists so
 * that opening the panel and typing nothing leaves nothing behind — but once
 * someone has actually asked something, there is nothing empty about the chat,
 * and waiting for the answer means the whole exchange lives only in memory for
 * as long as the model takes to produce one. A reload in that window used to
 * take the question, the half-written answer and the chat itself, and since no
 * resource had ever been created, the chat could not even be found afterwards.
 */
export const shouldFinalizeDraftChat = (message: AtomicUIMessage) =>
  message.role === 'user';

/**
 * Whether this chat still needs a name.
 *
 * Asked of the resource rather than of `isChatSaved`, which used to stand in
 * for it. Those were the same question only while a chat was saved at the
 * moment it was first titled; now that it is saved a message earlier, a shared
 * flag would report every chat as titled and none would ever get a name.
 */
export const needsTitle = (resource: DraftChatResource) =>
  (resource.get(core.properties.name) ?? DEFAULT_AICHAT_NAME) ===
  DEFAULT_AICHAT_NAME;

export const persistSidebarMessage = async ({
  message,
  newMessages,
  store,
  getOrCreateDraftChatResource,
  isChatSavedRef,
  titlePromiseRef,
  setMessageToResourceMap,
  messageToResourceMapRef,
  setIsChatSaved,
  shouldGenerateTitles,
  generateTitle,
}: PersistSidebarMessageArgs) => {
  const resource = await getOrCreateDraftChatResource();

  if (!resource) {
    return;
  }

  // Read once. The writes below are serialized per chat, so this call can
  // resolve on the far side of the draft finalization that this same flag
  // guards, and then disagree with itself about which branch it belongs in.
  const wasDraft = !isChatSavedRef.current;

  const messageResource = await addMessageToChatResource(
    message,
    resource,
    store,
    { persistToServer: !wasDraft },
  );

  // Persistence must not depend on React executing a deferred state updater.
  const next = new Map(messageToResourceMapRef.current);

  for (const key of next.keys()) {
    if (key.id === message.id) next.delete(key);
  }

  next.set(message, messageResource);
  messageToResourceMapRef.current = next;
  setMessageToResourceMap(next);

  if (wasDraft && shouldFinalizeDraftChat(message)) {
    // On the chat's own write queue, behind every message write already in
    // flight, so that no write can observe the chat as a draft after this
    // has stopped treating it as one.
    await queueChatWrite(resource, async () => {
      // Persist child messages (and their parts) before the chat resource
      // references them on the server — matches AIChatPage / addMessageToChatResource.
      for (const pendingMessageResource of messageToResourceMapRef.current.values()) {
        await persistMessageResourceToServer(pendingMessageResource, store);
      }

      await resource.save();

      isChatSavedRef.current = true;
      setIsChatSaved(true);
    });
  } else if (wasDraft && isChatSavedRef.current) {
    // Built as a draft, queued behind the writes that finalized the chat.
    // The sweep above runs for the user's message only, and a draft message
    // comes back from `uiMessageToResource` with a stashed genesis and
    // unsaved parts, so nothing else ever sends it: it is not in the outbox
    // and carries no dirty flag, which means no drain retries it and
    // `getSyncStatus` calls the tab fully synced while the message exists
    // here alone. For a streaming reply that is its last chunk — on screen,
    // absent from the server, and gone on the next reload, because the
    // checkpoint interval has already recorded the content it just wrote and
    // will not repeat itself.
    await persistMessageResourceToServer(messageResource, store);
    await resource.save();
  }

  // Naming starts on the question. Waiting for the reply left every chat whose
  // answer never landed (a reload, a failed request, a closed tab) as
  // "Untitled Chat" for ever. Decided here, where the resource is already in
  // hand, rather than in the component. The reply path still awaits a pending
  // title, and retries from both halves when the question alone produced none.
  if (
    !titlePromiseRef.current &&
    shouldGenerateTitles &&
    needsTitle(resource) &&
    (message.role === 'user' || newMessages.length >= 2)
  ) {
    titlePromiseRef.current = generateTitle(newMessages);
  }

  if (titlePromiseRef.current) {
    const pending = applyChatTitle(resource, titlePromiseRef, isChatSavedRef);

    if (message.role === 'assistant') await pending;
  }
};

/** Names the chat (and gives it an emoji) once the pending title resolves. */
async function applyChatTitle(
  resource: DraftChatResource,
  titlePromiseRef: PersistSidebarMessageArgs['titlePromiseRef'],
  isChatSavedRef: PersistSidebarMessageArgs['isChatSavedRef'],
) {
  const promise = titlePromiseRef.current;

  if (!promise) return;

  const generated = await promise;

  if (titlePromiseRef.current === promise) titlePromiseRef.current = undefined;

  if (!generated || !needsTitle(resource)) return;

  await resource.set(core.properties.name, generated.title);

  if (generated.emoji) {
    await resource.set(dataBrowser.properties.emoji, generated.emoji);
  }

  // Not while the chat is still a draft. A title can resolve before the
  // finalization has pushed the messages, and this save would then put the
  // chat on the server already pointing at children the server has not seen,
  // which is what the sweep's ordering exists to avoid. Whoever opens the chat
  // in that window gets "Resource not found" where the reply should be. The
  // name is set on the resource either way, so the finalization's own save
  // carries it.
  if (!isChatSavedRef.current) return;

  await resource.save();
}
