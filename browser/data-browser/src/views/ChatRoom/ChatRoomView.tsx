import {
  commits,
  core,
  dataBrowser,
  Resource,
  Store,
  useArray,
  useCanWrite,
  useCollection,
  useCreatedAt,
  useCreatedBy,
  useResource,
  useResourceSnapshot,
  useStore,
  useString,
  useSubject,
  useTypingPresence,
} from '@tomic/react';
import { memo, useCallback, useRef, useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import {
  FaCopy,
  FaLink,
  FaLocationArrow,
  FaMessage,
  FaPencil,
  FaReply,
  FaXmark,
} from 'react-icons/fa6';
import { styled } from 'styled-components';
import { AtomicLink } from '../../components/AtomicLink';
import { PresenceAvatarMenu } from '../../components/Presence/PresenceAvatarMenu';
import { Button } from '../../components/Button';
import { IconButton } from '../../components/IconButton/IconButton';
import { ChatMessagesContainer } from '../../components/ChatMessagesContainer';
import Markdown from '../../components/datatypes/Markdown';
import { Detail } from '../../components/Detail';
import { LoaderInline } from '../../components/Loader';
import { editURL } from '../../helpers/navigation';
import { formatCompactDateTime } from '../../helpers/dates/compactDateTime';
import { ResourceInline } from '../ResourceInline';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';
import { TypingIndicator } from '../../components/Presence/TypingIndicator';

const CHAT_PAGE_SIZE = 50;

export interface ChatViewProps {
  messages: string[];
  loading: boolean;
  /** Persists a message. Throwing restores the composer text and shows the error. */
  onSend: (text: string, replyTo?: string) => Promise<void>;
  /** Pass a ref to control composer focus from outside (e.g. after a title edit). */
  inputRef?: React.RefObject<HTMLTextAreaElement | null>;
  /** Give the composer the `chat-input` view-transition-name. Only ONE
   *  mounted chat may do this (the full-page ChatRoom) — duplicate names
   *  make the browser skip view transitions with a warning. */
  viewTransition?: boolean;
  /** Drop the message container's own padding — for hosts (panels) whose
   *  chrome already pads; message rows keep their inline padding. */
  noContainerPadding?: boolean;
  /** Subject keying "who is typing" presence: the resource for a comment
   *  thread, or the chatroom for a meeting/chat. Omit to disable the hint. */
  threadSubject?: string;
}

/**
 * Presentational chat: message list, reply state and composer. Data comes in
 * via props so it also works before a chat resource exists (e.g. the Comments
 * panel creates the discussion on the first send).
 */
export function ChatView({
  messages,
  loading: messagesLoading,
  onSend,
  inputRef: inputRefProp,
  viewTransition = false,
  noContainerPadding = false,
  threadSubject,
}: ChatViewProps) {
  const [newMessageVal, setNewMessage] = useState('');
  const [isReplyTo, setReplyTo] = useState<string | undefined>(undefined);
  const internalInputRef = useRef<HTMLTextAreaElement>(null);
  const inputRef = inputRefProp ?? internalInputRef;
  const [textAreaHight, setTextAreaHight] = useState(1);
  const [scrollToBottomTrigger, setScrollToBottomTrigger] = useState(0);

  const { typers, notifyTyping, stopTyping } = useTypingPresence(threadSubject);

  const disableSend = newMessageVal.length === 0;

  const sendMessage = async (e?: React.SyntheticEvent) => {
    e?.preventDefault();

    if (disableSend) {
      return;
    }

    const messageBackup = newMessageVal;

    try {
      setScrollToBottomTrigger(prev => prev + 1);
      setNewMessage('');
      stopTyping();
      await onSend(messageBackup, isReplyTo);
      setReplyTo(undefined);
    } catch (err) {
      setNewMessage(messageBackup);
      toast.error(err.message);
    }
  };

  const handleKeyDown: React.KeyboardEventHandler<HTMLTextAreaElement> = e => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    } else if (e.key === 'Escape') {
      inputRef.current?.blur();
    }
  };

  const handleReply = useCallback(
    (subject: string) => {
      setReplyTo(subject);
      inputRef.current?.focus();
    },
    [setReplyTo, inputRef],
  );

  const handleChangeMessageText: React.ChangeEventHandler<
    HTMLTextAreaElement
  > = e => {
    setNewMessage(e.target.value);

    if (e.target.value === '') {
      // Make the textarea small again when the user removed their message
      setTextAreaHight(1);
      stopTyping();

      return;
    }

    notifyTyping();

    // Auto-grow the textarea
    const overflowStyle = e.target.style.overflow;
    e.target.style.overflow = 'scroll';
    // in Firefox, scrollHeight only works if overflow is set to scroll
    const height = e.target.scrollHeight;
    e.target.style.overflow = overflowStyle;
    const rowHeight = 30;
    const trows = Math.ceil(height / rowHeight) - 1;

    if (trows !== textAreaHight) {
      setTextAreaHight(trows);
    }
  };

  return (
    <ViewWrapper>
      <ScrollAreaWrapper>
        <ChatMessagesContainer
          enableAutoScroll
          scrollToBottomTrigger={scrollToBottomTrigger}
          fullView={noContainerPadding}
        >
          {messagesLoading ? (
            <LoaderInline>Loading messages...</LoaderInline>
          ) : messages.length === 0 ? (
            <EmptyChatState>
              <FaMessage />
              <p>No messages yet</p>
              <span>Be the first to say something</span>
            </EmptyChatState>
          ) : (
            messages.map(message => (
              <Message
                key={message}
                subject={message}
                setReplyTo={handleReply}
              />
            ))
          )}
        </ChatMessagesContainer>
      </ScrollAreaWrapper>
      {isReplyTo && (
        <Detail>
          <MessageLine subject={isReplyTo} />
          <Button icon subtle onClick={() => setReplyTo(undefined)}>
            <FaXmark />
          </Button>
        </Detail>
      )}
      <TypingIndicator typers={typers} />
      <MessageForm onSubmit={sendMessage} $viewTransition={viewTransition}>
        <MessageInput
          aria-label='Chat input'
          rows={textAreaHight}
          ref={inputRef}
          autoFocus
          value={newMessageVal}
          onChange={handleChangeMessageText}
          onKeyDown={handleKeyDown}
          onBlur={stopTyping}
          placeholder={'type a message'}
        />
        <SendButton
          title='Send message [enter]'
          disabled={disableSend}
          clean
          onClick={() => sendMessage()}
        >
          Send
        </SendButton>
      </MessageForm>
    </ViewWrapper>
  );
}

export interface ChatRoomViewProps {
  resource: Resource;
  /** Pass a ref to control composer focus from outside (e.g. after a title edit). */
  inputRef?: React.RefObject<HTMLTextAreaElement | null>;
  /** See {@link ChatViewProps.viewTransition}. */
  viewTransition?: boolean;
  /** See {@link ChatViewProps.noContainerPadding}. */
  noContainerPadding?: boolean;
}

/**
 * Message list and composer for an existing ChatRoom. Used by the full-page
 * ChatRoom view and the Comments panel.
 */
export function ChatRoomView({
  resource,
  inputRef,
  viewTransition,
  noContainerPadding,
}: ChatRoomViewProps) {
  const store = useStore();
  const { messages, loading, invalidate } = useChatMessages(resource.subject);

  const handleSend = async (text: string, replyTo?: string) => {
    await sendChatMessage(store, { parent: resource.subject, text, replyTo });
    invalidate();
  };

  return (
    <ChatView
      messages={messages}
      loading={loading}
      onSend={handleSend}
      inputRef={inputRef}
      viewTransition={viewTransition}
      noContainerPadding={noContainerPadding}
      threadSubject={resource.subject}
    />
  );
}

interface SendChatMessageOptions {
  /** Rights/lifecycle anchor: the ChatRoom, or e.g. the drive's Comments folder for comments. */
  parent: string;
  text: string;
  /** For comments: the resource this message is about. The comment thread of a resource is the set of Messages with `about` pointing to it. */
  about?: string;
  replyTo?: string;
  /** Additional classes besides Message (e.g. FollowEvent for
   *  follow-session trail entries, which render as compact system lines). */
  extraClasses?: string[];
}

/** Creates and saves a Message resource. */
export async function sendChatMessage(
  store: Store,
  { parent, text, about, replyTo, extraClasses }: SendChatMessageOptions,
) {
  const msgResource = await store.newResource({
    parent,
    isA: [dataBrowser.classes.message, ...(extraClasses ?? [])],
    propVals: {
      [core.properties.description]: text,
      // `createdAt` is NOT set here: it's derived from the genesis Loro
      // change (timestamp) and materialized server-side. Authoring it
      // explicitly is now rejected by the server.
      ...(about && {
        [dataBrowser.properties.about]: about,
      }),
      ...(replyTo && {
        [dataBrowser.properties.replyTo]: replyTo,
      }),
    },
  });

  await msgResource.save();
  store.notifyResourceManuallyCreated(msgResource);
}

type SetReplyToType = (subject: string) => unknown;

interface MessageProps {
  subject: string;
  /** Is called when the `reply` button is pressed */
  setReplyTo: SetReplyToType;
}

/** How many characters are shown at max by default in a message */
const MESSAGE_MAX_LEN = 500;

/** Single message shown in a ChatRoom */
const Message = memo(function Message({ subject, setReplyTo }: MessageProps) {
  const resource = useResource(subject);
  const [description] = useString(resource, core.properties.description);
  const [isA] = useArray(resource, core.properties.isA);
  const isFollowEvent = isA.includes(dataBrowser.classes.followEvent);
  // Creation date + creator come from the genesis change in the resource's own
  // Loro oplog (materialized into propvals) — no commit fetch, so they survive
  // a refresh. The commit subject is intentionally NOT passed.
  const createdAt = useCreatedAt(resource);
  const createdBy = useCreatedBy(resource);
  const [replyTo] = useSubject(resource, dataBrowser.properties.replyTo);
  const navigate = useNavigateWithTransition();
  const canWrite = useCanWrite(resource);

  function handleCopyUrl() {
    navigator.clipboard.writeText(subject);
    toast.success('Copied message URL to clipboard');
  }

  if (isFollowEvent) {
    return (
      <FollowEventMessage
        description={description ?? ''}
        createdAt={createdAt}
        createdBy={createdBy}
      />
    );
  }

  function handleCopyText() {
    navigator.clipboard.writeText(description || '');
    toast.success('Copied message text to clipboard');
  }

  return (
    <MessageComponent about={subject}>
      {createdBy ? (
        <PresenceAvatarMenu agentSubject={createdBy} size='1.8rem' />
      ) : (
        <AvatarSpacer />
      )}
      <MessageBody>
        <MessageDetails>
          <MessageMeta createdAt={createdAt} createdBy={createdBy} />
          {replyTo && <MessageLine subject={replyTo} />}
          <MessageActions>
            {canWrite && (
              <IconButton
                onClick={() => navigate(editURL(subject))}
                title='Edit message'
              >
                <FaPencil />
              </IconButton>
            )}
            <IconButton
              onClick={() => setReplyTo(subject)}
              title='Reply to this message'
            >
              <FaReply />
            </IconButton>
            <IconButton
              onClick={handleCopyUrl}
              title='Copy link to this message'
            >
              <FaLink />
            </IconButton>
            <IconButton onClick={handleCopyText} title='Copy message text'>
              <FaCopy />
            </IconButton>
          </MessageActions>
        </MessageDetails>
        {/* markExternalLinks routes links through AtomicLink: subject links
            navigate in-app instead of triggering a full page load. */}
        <Markdown
          text={description || ''}
          maxLength={MESSAGE_MAX_LEN}
          markExternalLinks
        />
      </MessageBody>
    </MessageComponent>
  );
});

/** Compact message header: the author (truncated when the name/DID is long,
 *  so it never shoves the date off-row) and a short human timestamp. */
function MessageMeta({
  createdAt,
  createdBy,
}: {
  createdAt: Date | undefined;
  createdBy: string | undefined;
}) {
  return (
    <MessageMetaRow>
      {createdBy && (
        <MessageAuthor>
          {/* No glyph: the message already leads with the author's avatar. */}
          <ResourceInline subject={createdBy} hideGlyph />
        </MessageAuthor>
      )}
      {createdAt && (
        <MessageTime
          dateTime={createdAt.toISOString()}
          title={createdAt.toLocaleString()}
        >
          {formatCompactDateTime(createdAt)}
        </MessageTime>
      )}
    </MessageMetaRow>
  );
}

/** Matches the trail text written by the meeting/follow logger:
 *  `Viewing [title](subject)`. The markdown is kept as a fallback for
 *  clients without FollowEvent support; we render a live resource link. */
const TRAIL_TEXT_REGEX = /^Viewing \[.*\]\((\S+)\)$/;

/** Compact system-style line for meeting events (trail entries and
 *  start/end markers) — visually distinct from chat messages. Markers
 *  ("Started the meeting.", "The meeting has ended.") render verbatim;
 *  "Viewing […](…)" entries render as a live resource link. */
function FollowEventMessage({
  description,
  createdAt,
  createdBy,
}: {
  description: string;
  createdAt: Date | undefined;
  createdBy: string | undefined;
}) {
  const visited = description.match(TRAIL_TEXT_REGEX)?.[1];
  const text = description;

  return (
    <FollowEventLine>
      <FaLocationArrow />
      {/* Trail entries show only the visited resource — the author is the
          session's agent on every line, so repeating it is pure noise. */}
      {visited ? (
        <EventAuthor>
          <ResourceInline subject={visited} />
        </EventAuthor>
      ) : (
        <>
          {createdBy && (
            <EventAuthor>
              <ResourceInline subject={createdBy} />
            </EventAuthor>
          )}
          <EventText>{text}</EventText>
        </>
      )}
      {createdAt && (
        <EventTime
          dateTime={createdAt.toISOString()}
          title={createdAt.toLocaleString()}
        >
          {formatCompactDateTime(createdAt)}
        </EventTime>
      )}
    </FollowEventLine>
  );
}

const FollowEventLine = styled.div`
  display: flex;
  align-items: center;
  gap: 0.4ch;
  /* Line up with the chat messages (no extra inline padding). */
  padding: 0.1rem 0;
  color: ${p => p.theme.colors.textLight};
  font-size: 0.85rem;
  min-width: 0;

  & svg {
    font-size: 0.7rem;
    flex-shrink: 0;
  }
`;

/** The event's author/resource — truncates so a long name/DID can't push the
 *  time off the row. */
const EventAuthor = styled.span`
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

const EventText = styled.span`
  flex-shrink: 0;
  white-space: nowrap;
`;

const EventTime = styled.time`
  margin-left: auto;
  flex-shrink: 0;
  white-space: nowrap;
  padding-left: 0.5ch;
  font-size: 0.7rem;
  opacity: 0.7;
`;

interface MessageLineProps {
  subject: string;
}

const MESSAGE_LINE_MAX_LEN = 50;

/** Small single line preview of a message, useful in replies */
function MessageLine({ subject }: MessageLineProps) {
  const { resource, ready } = useResourceSnapshot(subject);
  const [description] = useString(resource, core.properties.description);
  // Author from the resource's own genesis metadata (createdBy) — not a commit
  // fetch, so it survives a refresh.
  const author = useCreatedBy(resource);

  if (!ready) {
    return <MessageLineStyled>loading...</MessageLineStyled>;
  }

  // truncate and add ellipsis
  const truncated = description?.substring(0, MESSAGE_LINE_MAX_LEN);
  const ellipsis =
    description && description.length > MESSAGE_LINE_MAX_LEN ? '...' : '';

  return (
    <MessageLineStyled>
      <span>to </span>
      {author && <ResourceInline subject={author} />}
      <AtomicLink subject={subject}>{`: ${truncated}${ellipsis}`}</AtomicLink>
    </MessageLineStyled>
  );
}

const MessageLineStyled = styled.span`
  font-size: 0.7rem;
  white-space: nowrap;
  overflow: hidden;
  flex: 1;
`;

/** Small row on top of Message for author, date and the hover actions. */
const MessageDetails = styled.div`
  font-size: 0.75rem;
  display: flex;
  align-items: center;
  gap: 1ch;
  width: 100%;
  min-width: 0;
  color: ${p => p.theme.colors.textLight};
`;

const MessageMetaRow = styled.div`
  display: flex;
  align-items: baseline;
  gap: 0.6ch;
  /* Let the author truncate rather than push the time out of view. */
  min-width: 0;
`;

const MessageAuthor = styled.span`
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

const MessageTime = styled.time`
  flex-shrink: 0;
  white-space: nowrap;
`;

/** The hover actions, pushed to the right of the meta row. */
const MessageActions = styled.div`
  display: flex;
  align-items: center;
  gap: 0.25ch;
  margin-left: auto;
  flex-shrink: 0;
  opacity: 0;
  color: ${p => p.theme.colors.textLight};
`;

/** Everything to the right of the avatar: meta row + message body. The hover
 *  highlight lives HERE — a rounded chip around the text only — so it never
 *  covers, clips, or crowds the avatar sitting to its left. */
const MessageBody = styled.div`
  flex: 1;
  min-width: 0;
  padding: 0.3rem 0.5rem;
  border-radius: ${p => p.theme.radius};
  /* Bleed a little into the panel's right padding so the chip isn't cramped. */
  margin-right: -0.5rem;
`;

/** Keeps authorless messages aligned with the avatared ones. */
const AvatarSpacer = styled.div`
  width: 1.8rem;
  flex-shrink: 0;
`;

const MessageComponent = styled.div`
  display: flex;
  align-items: flex-start;
  /* Enough room that the avatar's hover ring never touches the body chip. */
  gap: 0.75rem;
  padding-block: 0.1rem;

  &:hover ${MessageBody} {
    background: ${p => p.theme.colors.bg1};
  }

  &:hover ${MessageActions}, &:focus-within ${MessageActions} {
    opacity: 1;
  }
`;

const SendButton = styled(Button)`
  padding-left: 1rem;
  padding-right: 1rem;
  color: ${p => p.theme.colors.bg};
  background: ${p => p.theme.colors.main};

  &:disabled {
    cursor: default;
    display: auto;
    opacity: 0.5;
  }
`;

const MessageInput = styled.textarea`
  color: ${p => p.theme.colors.text};
  background: none;
  flex: 1;
  padding: 0.5rem 1rem;
  border: ${p => p.theme.colors.bg2} solid 1px;
  border-right: none;
  line-height: inherit;
  min-height: 2rem;
  max-height: 50vh;
  font-family: ${p => p.theme.fontFamily};
`;

/** Wrapper for the new message form */
const MessageForm = styled.form<{ $viewTransition?: boolean }>`
  display: flex;
  flex-basis: 3rem;
  flex-direction: row;
  border-radius: ${p => p.theme.radius};
  background: ${p => p.theme.colors.bg};

  view-transition-name: ${p => (p.$viewTransition ? 'chat-input' : 'none')};

  > :first-child {
    border-top-left-radius: ${p => p.theme.radius};
    border-bottom-left-radius: ${p => p.theme.radius};
  }
  > :last-child {
    border-top-right-radius: ${p => p.theme.radius};
    border-bottom-right-radius: ${p => p.theme.radius};
  }
`;

const ViewWrapper = styled.div`
  display: flex;
  flex-direction: column;
  flex: 1;
  min-height: 0;
  gap: ${p => p.theme.size(2)};
`;

const ScrollAreaWrapper = styled.div`
  flex: 1;
  min-height: 0;
`;

const EmptyChatState = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 0.4rem;
  padding-block: 4rem;
  color: ${p => p.theme.colors.textLight};
  opacity: 0.5;

  & > svg {
    font-size: 2.5rem;
    margin-bottom: 0.5rem;
  }

  & > p {
    margin: 0;
    font-size: 1rem;
    font-weight: 500;
  }

  & > span {
    font-size: 0.8rem;
  }
`;

// `about` is also used by AI chats; only Messages belong in a chat/comment thread.
const ONLY_MESSAGES = [
  { property: core.properties.isA, value: dataBrowser.classes.message },
];

/**
 * Fetches messages linked to a subject using the Collection system, sorted by
 * createdAt ascending (oldest first) with pagination. ChatRooms link their
 * messages via `parent` (the default); comment threads via `about`.
 */
export function useChatMessages(
  subject: string,
  property: string = core.properties.parent,
) {
  const [messages, setMessages] = useState<string[]>([]);

  const { collection, ready, invalidateCollection } = useCollection(
    {
      property,
      value: subject,
      filters: ONLY_MESSAGES,
      sort_by: commits.properties.createdAt,
      sort_desc: false,
    },
    { pageSize: CHAT_PAGE_SIZE },
  );

  useEffect(() => {
    const extractMembers = async () => {
      await collection.waitForReady();
      const members: string[] = [];

      for (let i = 0; i < collection.totalMembers; i++) {
        const member = await collection.getMemberWithIndex(i);

        if (member) {
          members.push(member);
        }
      }

      setMessages(members);
    };

    extractMembers();
  }, [collection]);

  // `useCollection` (used internally by this hook) routes
  // `ResourceManuallyCreated` through `applyResourceChange` for an
  // optimistic append — sent messages appear instantly without a
  // server round-trip.

  return {
    messages,
    loading: !ready,
    invalidate: invalidateCollection,
  };
}
