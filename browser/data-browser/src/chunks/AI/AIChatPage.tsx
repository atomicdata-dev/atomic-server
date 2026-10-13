import { useEffect, useState } from 'react';
import { Ai, dataBrowser, useCanWrite, useStore, useTitle } from '@tomic/react';
import type { ResourcePageProps } from '@views/ResourcePage';
import toast from 'react-hot-toast';
import { type AIMessageContext, type AtomicUIMessage } from './types';
import { Column, Row } from '@components/Row';
import { EditableTitle } from '@components/EditableTitle';
import { ResourceContextMenu } from '@components/ResourceContextMenu';
import { ResourceCoverImage } from '@components/ResourceDecorations';
import { DEFAULT_AICHAT_NAME } from '@components/AI/aiContstants';
import { useGenerativeData } from './useGenerativeData';
import {
  addMessageToChatResource,
  type AiMessageRef,
  loadChatMessages,
  removeFollowingMessagesFromChatResource,
  removeMessageFromChatResource,
} from './chatConversionUtils';
import { RealAIChat } from './RealAIChat';
import { useAISettings } from '@components/AI/AISettingsContext';
import { styled } from 'styled-components';
import { consumePendingFirstMessage } from './pendingFirstMessage';
import { userTiming } from '@helpers/userTiming';
import { Spinner } from '@components/Spinner';

const AIChatPage: React.FC<ResourcePageProps<Ai.AiChat>> = ({ resource }) => {
  const store = useStore();
  const { shouldGenerateTitles } = useAISettings();
  const [loading, setLoading] = useState(true);
  const [messages, setMessages] = useState<AtomicUIMessage[]>([]);
  const [compactedMessages, setCompactedMessages] = useState<AtomicUIMessage[]>(
    [],
  );
  const [contextItems, setContextItems] = useState<AIMessageContext[]>([]);
  const [messageToResourceMap, setMessageToResourceMap] = useState(
    new Map<AtomicUIMessage, AiMessageRef>(),
  );
  const [title, setTitle] = useTitle(resource);
  const [autoSubmitMessage, setAutoSubmitMessage] = useState<string>();

  const canWrite = useCanWrite(resource);
  const { generateTitleFromConversation } = useGenerativeData();

  const addNewMessage = async (message: AtomicUIMessage) => {
    setMessages(prev =>
      prev.some(m => m.id === message.id)
        ? prev.map(m => (m.id === message.id ? message : m))
        : [...prev, message],
    );

    const newMessages = [...messages, message];

    // Name the chat from the first question so it never stays "Untitled Chat"
    // when the reply fails to land. The reply retries if that produced nothing.
    if (
      newMessages.length <= 2 &&
      title === DEFAULT_AICHAT_NAME &&
      shouldGenerateTitles
    ) {
      generateTitleFromConversation(newMessages).then(generated => {
        if (!generated) return;
        setTitle(generated.title);

        if (generated.emoji) {
          void resource
            .set(dataBrowser.properties.emoji, generated.emoji)
            .then(() => resource.save());
        }
      });
    }

    try {
      const messageResource = await addMessageToChatResource(
        message,
        resource,
        store,
      );

      setMessageToResourceMap(prev => {
        const next = new Map(prev);

        for (const key of next.keys()) {
          if (key.id === message.id) next.delete(key);
        }

        next.set(message, messageResource);

        return next;
      });
    } catch (error) {
      console.error(error);
      toast.error('Failed to create message resource');
    }
  };

  const handleSummaryDeleted = (restored: AtomicUIMessage[]) => {
    setCompactedMessages([]);
    setMessages(restored);
  };

  const handleDeleteMessage = async (message: AtomicUIMessage) => {
    const messageResource = messageToResourceMap.get(message);

    if (messageResource) {
      try {
        await removeMessageFromChatResource(messageResource, resource, store);
      } catch (error) {
        console.error('Error removing message:', error);
        toast.error('Failed to remove message resource');
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

    setMessages(prev => prev.filter(m => m !== message));
  };

  const handleCompacted = async (
    priorMessages: AtomicUIMessage[],
    summaryMessage: AtomicUIMessage,
  ) => {
    setCompactedMessages(prev => [...prev, ...priorMessages]);
    setMessages([summaryMessage]);

    try {
      const messageResource = await addMessageToChatResource(
        summaryMessage,
        resource,
        store,
      );

      setMessageToResourceMap(prev => {
        const next = new Map(prev);
        next.set(summaryMessage, messageResource);

        return next;
      });
    } catch (error) {
      console.error(error);
      toast.error('Failed to save summary message');
    }
  };

  const removeFollowingMessages = async (message: AtomicUIMessage) => {
    const isHistorical = compactedMessages.some(m => m.id === message.id);
    const allMessages = isHistorical
      ? [...compactedMessages, ...messages]
      : messages;

    try {
      const newMessages = await removeFollowingMessagesFromChatResource(
        message,
        allMessages,
        messageToResourceMap,
        resource,
        store,
      );

      setMessageToResourceMap(prev => {
        const next = new Map(prev);

        for (const m of allMessages.slice(newMessages.length)) {
          next.delete(m);
        }

        return next;
      });

      if (isHistorical) {
        setCompactedMessages([]);
      }

      setMessages(newMessages);
    } catch (error) {
      console.error('Error removing messages:', error);
    }
  };

  // On load create AIChatDisplayMessages from the resource's messages.
  useEffect(() => {
    const timing = userTiming('chat:page');
    loadChatMessages(resource, store).then(map => {
      timing.step('load');
      const allMessages = Array.from(map.keys());
      const lastSummaryIndex = allMessages.findLastIndex(
        m => m.metadata?.isSummary,
      );

      if (lastSummaryIndex > 0) {
        setCompactedMessages(allMessages.slice(0, lastSummaryIndex));
        setMessages(allMessages.slice(lastSummaryIndex));
      } else {
        setMessages(allMessages);
      }

      setMessageToResourceMap(map);
      setLoading(false);
      // Two frames later the list is on screen: that is the render cost.
      requestAnimationFrame(() =>
        requestAnimationFrame(() => timing.step('render')),
      );

      // A brand-new chat (e.g. from the search overlay's "Start AI Chat
      // with ..." action) may have a first message waiting to be sent.
      if (allMessages.length === 0) {
        setAutoSubmitMessage(consumePendingFirstMessage(resource.subject));
      }
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (loading) {
    return <Spinner centered />;
  }

  return (
    <RealAIChat
      fullView
      initialMessages={messages}
      historicalMessages={compactedMessages}
      readonly={!canWrite}
      externalContextItems={contextItems}
      setExternalContextItems={setContextItems}
      chatSubject={resource.subject}
      autoSubmitMessage={autoSubmitMessage}
      onNewMessage={addNewMessage}
      onCompacted={handleCompacted}
      onSummaryDeleted={handleSummaryDeleted}
      onDeleteMessage={handleDeleteMessage}
      onRegenerateMessage={removeFollowingMessages}
    >
      <Column gap='0.5rem'>
        <ResourceCoverImage resource={resource} />
        <Row center justify='space-between'>
          <SmallTitle resource={resource} withDecorations />
          <ResourceContextMenu
            subject={resource.subject}
            title='Chat resource actions'
            searchable
          />
        </Row>
      </Column>
    </RealAIChat>
  );
};

export default AIChatPage;

const SmallTitle = styled(EditableTitle)`
  font-size: 1rem;
`;
