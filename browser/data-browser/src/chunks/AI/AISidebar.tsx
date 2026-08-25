import { styled } from 'styled-components';
import React, {
  useCallback,
  useEffect,
  useReducer,
  useRef,
  useState,
} from 'react';
import { newContextItem, useAISidebar } from '@components/AI/AISidebarContext';
import { AIAtomicResourceMessageContext, type AtomicUIMessage } from './types';
import { useCurrentSubject } from '@helpers/useCurrentSubject';
import { FaPlus, FaXmark } from 'react-icons/fa6';
import { IconButton } from '@components/IconButton/IconButton';
import { Row } from '@components/Row';
import {
  ai,
  core,
  dataBrowser,
  useStore,
  type Ai,
  type Resource,
} from '@tomic/react';
import { useGenerativeData } from './useGenerativeData';
import {
  messageResourcesToDisplayMessages,
  removeFollowingMessagesFromChatResource,
  removeMessageFromChatResource,
} from './chatConversionUtils';
import { findLatestAiChatAbout } from './findLatestAiChatAbout';
import {
  persistSidebarMessage,
  type TitlePromise,
} from './persistSidebarMessage';
import { getOrCreateAiChatsFolder } from '@helpers/standardLocations';
import { RealAIChat } from './RealAIChat';
import { useAISettings } from '@components/AI/AISettingsContext';
import { DEFAULT_AICHAT_NAME } from '@components/AI/aiContstants';
import { usePrivateDrive } from '@hooks/usePrivateDrive';
import toast from 'react-hot-toast';

const handleSidebarMessageSaveError = (error: unknown) => {
  console.error(error);
  toast.error('Failed to save AI chat message');
};

const AISidebar: React.FC = () => {
  const store = useStore();
  const [rerenderKey, updateRenderKey] = useReducer(prev => prev + 1, 0);
  const { shouldGenerateTitles } = useAISettings();
  const {
    isOpen,
    contextItems,
    setContextItems,
    setIsOpen,
    pendingAsk,
    clearPendingAsk,
  } = useAISidebar();
  const [autoSubmitMessage, setAutoSubmitMessage] = useState<string>();
  const { privateDrive } = usePrivateDrive();

  const [messages, setMessages] = useState<AtomicUIMessage[]>([]);
  const [compactedMessages, setCompactedMessages] = useState<AtomicUIMessage[]>(
    [],
  );
  // The chat callbacks can fire before React has committed the latest state, so
  // keep mutable mirrors for values that async persistence logic must read.
  const messagesRef = useRef<AtomicUIMessage[]>([]);
  const [chatResource, setChatResource] = useState<Resource<Ai.AiChat>>();
  const chatResourceRef = useRef<Resource<Ai.AiChat> | undefined>(undefined);
  const [isChatSaved, setIsChatSaved] = useState(false);
  const isChatSavedRef = useRef(false);
  // Draft creation starts on the first message; store the in-flight promise so
  // concurrent persistence calls share the same resource.
  const draftChatPromiseRef = useRef<Promise<Resource<Ai.AiChat>> | null>(null);
  const messageToResourceMapRef = useRef(new Map<AtomicUIMessage, Resource>());
  // Incremented when starting a new chat to ignore stale async resource
  // creation from the previous conversation.
  const chatGenerationRef = useRef(0);
  const [messageToResourceMap, setMessageToResourceMap] = useState(
    new Map<AtomicUIMessage, Resource>(),
  );
  const [currentSubject] = useCurrentSubject();
  const titlePromiseRef = useRef<TitlePromise | undefined>(undefined);
  const autoContextSubjectRef = useRef<string | undefined>(undefined);
  // Subject for which a re-open lookup already ran (or was suppressed).
  const reopenAttemptRef = useRef<string | undefined>(undefined);
  // Mirror for async draft creation, which runs outside the render cycle.
  const currentSubjectRef = useRef<string | undefined>(undefined);

  useEffect(() => {
    currentSubjectRef.current = currentSubject;
  }, [currentSubject]);
  const { generateTitleFromConversation } = useGenerativeData();

  const getOrCreateDraftChatResource = useCallback(async () => {
    if (chatResourceRef.current) {
      return chatResourceRef.current;
    }

    if (!privateDrive) {
      return undefined;
    }

    const generation = chatGenerationRef.current;

    if (!draftChatPromiseRef.current) {
      // Chats live in the personal drive's "AI Chats" folder (a standard
      // location) instead of cluttering the drive root. `about` records which
      // resource the chat was started on, so the sidebar can re-open it when
      // the user returns to that resource.
      const aboutSubject =
        autoContextSubjectRef.current ?? currentSubjectRef.current;
      draftChatPromiseRef.current = getOrCreateAiChatsFolder(
        store,
        privateDrive,
      ).then(folder =>
        store.newResource<Ai.AiChat>({
          parent: folder,
          isA: ai.classes.aiChat,
          propVals: {
            [core.properties.name]: DEFAULT_AICHAT_NAME,
            ...(aboutSubject && {
              [dataBrowser.properties.about]: aboutSubject,
            }),
          },
        }),
      );
    }

    const draftChatPromise = draftChatPromiseRef.current;
    const newChatResource = await draftChatPromise;

    if (draftChatPromiseRef.current === draftChatPromise) {
      draftChatPromiseRef.current = null;
    }

    if (generation !== chatGenerationRef.current) {
      return undefined;
    }

    chatResourceRef.current = newChatResource;
    setChatResource(newChatResource);

    return newChatResource;
  }, [privateDrive, store]);

  /**
   * Loads a previously saved chat into the sidebar (used to re-open the chat
   * that was created on the current resource). Mirrors AIChatPage's loading:
   * convert the chat's message resources to display messages and split off
   * everything before the last compaction summary.
   */
  const loadExistingChat = useCallback(
    async (chatSubject: string) => {
      const generation = chatGenerationRef.current;
      const chatRes = await store.getResource<Ai.AiChat>(chatSubject);
      const messageSubjects =
        (chatRes.get(ai.properties.messages) as string[] | undefined) ?? [];
      const map = await messageResourcesToDisplayMessages(
        messageSubjects,
        store,
      );

      if (generation !== chatGenerationRef.current) {
        return;
      }

      const allMessages = Array.from(map.keys());
      const lastSummaryIndex = allMessages.findLastIndex(
        m => m.metadata?.isSummary,
      );
      const visible =
        lastSummaryIndex > 0
          ? allMessages.slice(lastSummaryIndex)
          : allMessages;
      const historical =
        lastSummaryIndex > 0 ? allMessages.slice(0, lastSummaryIndex) : [];

      chatResourceRef.current = chatRes;
      setChatResource(chatRes);
      isChatSavedRef.current = true;
      setIsChatSaved(true);
      messagesRef.current = visible;
      setMessages(visible);
      setCompactedMessages(historical);
      messageToResourceMapRef.current = map;
      setMessageToResourceMap(map);
      // Remount RealAIChat so useChat re-seeds from initialMessages.
      updateRenderKey();
    },
    [store],
  );

  const handleCompacted = (
    priorMessages: AtomicUIMessage[],
    summaryMessage: AtomicUIMessage,
  ) => {
    setCompactedMessages(prev => [...prev, ...priorMessages]);
    messagesRef.current = [summaryMessage];
    setMessages([summaryMessage]);

    persistSidebarMessage({
      message: summaryMessage,
      newMessages: [summaryMessage],
      store,
      getOrCreateDraftChatResource,
      isChatSavedRef,
      titlePromiseRef,
      shouldGenerateTitles,
      generateTitle: generateTitleFromConversation,
      setMessageToResourceMap,
      messageToResourceMapRef,
      setIsChatSaved,
    }).catch(handleSidebarMessageSaveError);
  };

  const addNewMessage = (message: AtomicUIMessage) => {
    const newMessages = [...messagesRef.current, message];

    messagesRef.current = newMessages;
    setMessages(newMessages);

    persistSidebarMessage({
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
      generateTitle: generateTitleFromConversation,
    }).catch(handleSidebarMessageSaveError);
  };

  const handleSummaryDeleted = (restored: AtomicUIMessage[]) => {
    setCompactedMessages([]);
    messagesRef.current = restored;
    setMessages(restored);
  };

  const handleMessageDelete = async (message: AtomicUIMessage) => {
    const messageResource = messageToResourceMap.get(message);

    if (chatResource && messageResource) {
      try {
        await removeMessageFromChatResource(messageResource, chatResource, {
          saveChat: isChatSavedRef.current,
        });
      } catch (error) {
        console.error('Error removing message:', error);
        toast.error('Failed to remove AI chat message');
      }
    }

    setMessageToResourceMap(prev => {
      const next = new Map(prev);
      next.delete(message);

      return next;
    });

    if (message.metadata?.isSummary) {
      return;
    }

    const nextMessages = messagesRef.current.filter(m => m !== message);
    messagesRef.current = nextMessages;
    setMessages(nextMessages);
  };

  const startNewChat = useCallback(() => {
    // The user explicitly wants a fresh chat — don't immediately re-open the
    // existing chat for the resource they're viewing.
    reopenAttemptRef.current = currentSubject;
    chatGenerationRef.current += 1;
    draftChatPromiseRef.current = null;
    chatResourceRef.current = undefined;
    setChatResource(undefined);
    isChatSavedRef.current = false;
    setIsChatSaved(false);
    setMessages([]);
    setCompactedMessages([]);
    messagesRef.current = [];
    messageToResourceMapRef.current = new Map();
    setMessageToResourceMap(new Map());
    titlePromiseRef.current = undefined;
    autoContextSubjectRef.current = undefined;
    setContextItems([]);
    updateRenderKey();
    // Everything above is a ref or a setState, both stable — so this identity
    // only changes with the subject, and the effect below can depend on it.
  }, [currentSubject, setContextItems]);

  // A question asked from elsewhere in the app — the error bar over a broken
  // app being the first caller. Always a NEW chat: auto-submit only fires on
  // an empty one, and a bug report does not belong in the middle of whatever
  // conversation happened to be open.
  //
  // An effect rather than an event handler because the ask can be made while
  // this component is unmounted (the panel was closed), which is why it waits
  // in the context provider at all. Arriving here IS the external event.
  useEffect(() => {
    if (!pendingAsk) return;

    startNewChat();

    if (pendingAsk.context?.length) {
      // After startNewChat, which clears them.
      setContextItems(pendingAsk.context);
    }

    setAutoSubmitMessage(pendingAsk.prompt);
    // Clearing it is what stops this repeating: `startNewChat` is redefined
    // every render, so this effect runs after every render and the guard above
    // is what makes all but the first a no-op.
    clearPendingAsk();
  }, [pendingAsk, startNewChat, setContextItems, clearPendingAsk]);

  const onRegenerateMessage = async (message: AtomicUIMessage) => {
    const isHistorical = compactedMessages.some(m => m.id === message.id);
    const allMessages = isHistorical
      ? [...compactedMessages, ...messages]
      : messages;

    if (chatResource) {
      try {
        const trimmedMessages = await removeFollowingMessagesFromChatResource(
          message,
          allMessages,
          messageToResourceMap,
          chatResource,
          { saveChat: isChatSavedRef.current },
        );

        setMessageToResourceMap(prev => {
          const next = new Map(prev);

          for (const m of allMessages.slice(trimmedMessages.length)) {
            next.delete(m);
          }

          return next;
        });

        if (isHistorical) {
          setCompactedMessages([]);
        }

        messagesRef.current = trimmedMessages;
        setMessages(trimmedMessages);
        titlePromiseRef.current = undefined;
      } catch (error) {
        console.error('Error removing messages:', error);
        toast.error('Failed to regenerate AI chat message');
      }

      return;
    }

    // Remove all messages after the one that was regenerated
    const trimmedMessages = allMessages.slice(
      0,
      allMessages.findIndex(x => x.id === message.id) + 1,
    );

    if (isHistorical) {
      setCompactedMessages([]);
    }

    messagesRef.current = trimmedMessages;
    setMessages(trimmedMessages);
    titlePromiseRef.current = undefined;
  };

  useEffect(() => {
    if (sessionStorage.getItem('atomic.ai.openSetup') === 'true') {
      setIsOpen(true);
    }
  }, [setIsOpen]);

  // When the personal home drive changes, cached resource refs belong to the old
  // drive. Clear them so the next call to getOrCreateDraftChatResource creates
  // a fresh resource on the correct drive. Incrementing chatGenerationRef also
  // causes any still-resolving promises from the previous drive to be ignored.
  useEffect(() => {
    chatGenerationRef.current += 1;
    draftChatPromiseRef.current = null;
    chatResourceRef.current = undefined;
  }, [privateDrive]);

  // Re-open the chat that was created on the current resource: when the
  // sidebar is open on subject X with a completely empty chat, load the most
  // recent saved chat whose `about` points at X. Attempted once per subject
  // so a not-found result (or an explicit New Chat) doesn't re-query forever.
  // Waits for `privateDrive`: its resolution bumps chatGenerationRef (see the
  // effect above), which would discard a lookup started before it.
  useEffect(() => {
    if (!isOpen || !currentSubject || !privateDrive) {
      return;
    }

    if (
      messagesRef.current.length > 0 ||
      chatResourceRef.current ||
      isChatSavedRef.current ||
      reopenAttemptRef.current === currentSubject
    ) {
      return;
    }

    reopenAttemptRef.current = currentSubject;
    const generation = chatGenerationRef.current;

    findLatestAiChatAbout(store, currentSubject)
      .then(found => {
        if (
          !found ||
          generation !== chatGenerationRef.current ||
          messagesRef.current.length > 0 ||
          chatResourceRef.current
        ) {
          return;
        }

        return loadExistingChat(found);
      })
      .catch(error => {
        console.error('Failed to re-open AI chat for resource:', error);
      });
  }, [isOpen, currentSubject, privateDrive, store, loadExistingChat]);

  useEffect(() => {
    // Avoid re-adding the same subject after the user removes or changes the
    // auto-inserted context item.
    // When the user opens the AI sidebar and the chat is completely empty, we add the current subject to the context.
    if (
      isOpen &&
      currentSubject &&
      messages.length === 0 &&
      contextItems.length < 2 &&
      autoContextSubjectRef.current !== currentSubject
    ) {
      autoContextSubjectRef.current = currentSubject;
      setContextItems([
        newContextItem<AIAtomicResourceMessageContext>({
          type: 'atomic-resource',
          subject: currentSubject,
        }),
      ]);
    }
  }, [
    isOpen,
    currentSubject,
    messages.length,
    contextItems.length,
    setContextItems,
  ]);

  useEffect(() => {
    messagesRef.current = messages;
  }, [messages]);

  return (
    <React.Fragment key={rerenderKey}>
      {/* When resetting the chat it is better to refresh the whole component because the useChat hook keeps internal state that is not easy to reset. */}
      <RealAIChat
        autoSubmitMessage={autoSubmitMessage}
        initialMessages={messages}
        historicalMessages={compactedMessages}
        onNewMessage={addNewMessage}
        onCompacted={handleCompacted}
        onSummaryDeleted={handleSummaryDeleted}
        externalContextItems={contextItems}
        setExternalContextItems={setContextItems}
        chatSubject={isChatSaved ? chatResource?.subject : undefined}
        onDeleteMessage={handleMessageDelete}
        onRegenerateMessage={onRegenerateMessage}
      >
        <Row center justify='space-between' fullWidth>
          <Row center gap='0.5ch'>
            <IconButton
              title='New Chat'
              onClick={startNewChat}
              color='textLight'
              style={{ alignSelf: 'flex-end' }}
            >
              <FaPlus />
            </IconButton>
            <Heading>Atomic Assistant</Heading>
          </Row>
          <Row center gap='0.5ch'>
            <IconButton
              title='Close AI Sidebar'
              color='textLight'
              style={{ alignSelf: 'flex-end' }}
              onClick={() => {
                setIsOpen(false);
              }}
            >
              <FaXmark />
            </IconButton>
          </Row>
        </Row>
      </RealAIChat>
    </React.Fragment>
  );
};

const Heading = styled.h2`
  font-size: 1rem;
  font-weight: 600;
  margin-bottom: ${p => p.theme.size(2)};
`;

export default AISidebar;
