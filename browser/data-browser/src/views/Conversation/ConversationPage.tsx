import {
  conversations,
  core,
  useStore,
  useString,
  type Agent,
  type Store,
} from '@tomic/react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { FaLock } from 'react-icons/fa6';
import { styled } from 'styled-components';
import { Column } from '../../components/Row';
import { useSettings } from '../../helpers/AppSettings';
import {
  openPayloads,
  type SealedPayload,
} from '../../helpers/conversations/conversationCrypto';
import { parseEntryId } from '../../helpers/chatLog';
import { sendSealedMessage } from '../../helpers/conversations/conversations';
import { ChatView, useChatMessages } from '../ChatRoom/ChatRoomView';
import type { ResourcePageProps } from '../ResourcePage';
import { ConversationTitle } from './ConversationTitle';
import { resolveReplies, SealedMessagesContext } from './sealedMessages';

/**
 * An end-to-end encrypted conversation: the chat, with each message opened
 * here before it is shown. What the host stores, and what anyone outside the
 * conversation can fetch, is ciphertext.
 */
export function ConversationPage({ resource }: ResourcePageProps) {
  const store = useStore();
  const { agent } = useSettings();
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const [keyring] = useString(
    resource,
    conversations.properties.conversationKeys,
  );
  const { messages, loading, invalidate } = useChatMessages(
    resource.subject,
    core.properties.parent,
    true,
  );
  const payloads = useOpenedMessages(
    store,
    agent,
    keyring,
    resource.subject,
    messages,
  );
  const opened = useMemo(
    () => resolveReplies(payloads, messages),
    [payloads, messages],
  );

  // The conversation is a drive of its own, never the open one, so its new
  // messages only arrive with a subscription of their own.
  useEffect(() => store.subscribeLive(resource.subject), [store, resource]);

  const handleSend = async (text: string, replyTo?: string) => {
    await sendSealedMessage(store, resource, text, replyTo);
    invalidate();
  };

  return (
    <PageWrapper>
      <Column fullHeight>
        <Header>
          <Title data-testid='conversation-title'>
            <ConversationTitle resource={resource} />
          </Title>
          <Encrypted>
            <FaLock />
            <span>
              End-to-end encrypted. Only the people in this conversation can
              read it.
            </span>
          </Encrypted>
        </Header>
        <SealedMessagesContext.Provider value={opened}>
          <ChatView
            messages={messages}
            loading={loading}
            onSend={handleSend}
            inputRef={inputRef}
            viewTransition
            threadSubject={resource.subject}
          />
        </SealedMessagesContext.Provider>
      </Column>
    </PageWrapper>
  );
}

const NONE_OPENED: Map<string, SealedPayload | null> = new Map();

/** Opens each sealed message once, as it shows up in `messages`. */
function useOpenedMessages(
  store: Store,
  agent: Agent | undefined,
  keyring: string | undefined,
  conversation: string,
  messages: string[],
): Map<string, SealedPayload | null> {
  // Keyed by keyring: after a new epoch, messages that could not be opened
  // with the old one get another try.
  const [state, setState] = useState<{
    keyring: string | undefined;
    opened: Map<string, SealedPayload | null>;
  }>(() => ({ keyring, opened: new Map() }));
  const opened = state.keyring === keyring ? state.opened : NONE_OPENED;

  useEffect(() => {
    if (!agent || !keyring) return;

    const pending = messages.filter(message => !opened.has(message));

    if (pending.length === 0) return;

    let cancelled = false;

    const run = async () => {
      // An id is a log entry (`<page>#<key>`, what is written now) or a
      // SealedMessage resource that was not moved into the log yet.
      const sealed = (
        await Promise.all(
          pending.map(async id => {
            const entryId = parseEntryId(id);

            if (entryId) {
              const page = await store.getResource(entryId.page);
              const value = page.getChatLogEntry(entryId.key)?.s;

              return typeof value === 'string' ? [{ subject: id, value }] : [];
            }

            const message = await store.getResource(id);
            const value = message.get(conversations.properties.sealed);

            return typeof value === 'string' ? [{ subject: id, value }] : [];
          }),
        )
      ).flat();
      const payloads = await openPayloads(
        agent,
        keyring,
        conversation,
        sealed.map(message => message.value),
      );

      if (cancelled) return;

      setState(prev => {
        const next = new Map(prev.keyring === keyring ? prev.opened : []);
        sealed.forEach((message, i) => next.set(message.subject, payloads[i]));

        return { keyring, opened: next };
      });
    };

    run().catch(error => store.notifyError(error));

    return () => {
      cancelled = true;
    };
  }, [store, agent, keyring, conversation, messages, opened]);

  return opened;
}

const PageWrapper = styled.div`
  display: flex;
  flex-direction: column;
  height: 100%;
  padding: 1rem;
  min-height: 0;
`;

const Header = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
`;

const Title = styled.h1`
  margin: 0;
  font-size: 1.6rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

const Encrypted = styled.p`
  display: flex;
  align-items: center;
  gap: 0.5ch;
  margin: 0;
  font-size: 0.8rem;
  color: ${p => p.theme.colors.textLight};

  & svg {
    flex-shrink: 0;
  }
`;
