import { useMessageSpeaker } from '../../chunks/Demo/messageSpeaker';
import {
  commits,
  conversations,
  core,
  dataBrowser,
  Resource,
  server,
  Store,
  useArray,
  useCanWrite,
  useCollection,
  useCreatedAt,
  useCurrentAgent,
  useResource,
  useResourceSnapshot,
  useStore,
  useString,
  useSubject,
  useTypingPresence,
} from '@tomic/react';
import { memo, useRef, useState, useEffect, useLayoutEffect } from 'react';
import {
  appendToChatLog,
  deleteLogEntry,
  editLogEntry,
  hideMigrated,
  isFollowEntry,
  parseEntryId,
  sendLogEntry,
  scopeKey,
  queryPages,
  toEntryId,
  windowChat,
  type Timed,
} from '../../helpers/chatLog';
import {
  useChatLogEntry,
  useChatLogPages,
  useChatLogRevision,
} from '../../hooks/useChatLog';
import toast from 'react-hot-toast';
import {
  FaCopy,
  FaLink,
  FaLocationArrow,
  FaMessage,
  FaPencil,
  FaTrash,
  FaReply,
  FaXmark,
} from 'react-icons/fa6';
import { css, keyframes, styled } from 'styled-components';
import { AtomicLink } from '../../components/AtomicLink';
import { PresenceAvatarMenu } from '../../components/Presence/PresenceAvatarMenu';
import { Button } from '../../components/Button';
import { IconButton } from '../../components/IconButton/IconButton';
import { ChatMessagesContainer } from '../../components/ChatMessagesContainer';
import Markdown from '../../components/datatypes/Markdown';
import { Detail } from '../../components/Detail';
import { Spinner } from '../../components/Spinner';
import { editURL } from '../../helpers/navigation';
import { formatCompactDateTime } from '../../helpers/dates/compactDateTime';
import { ResourceInline } from '../ResourceInline';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';
import { TypingIndicator } from '../../components/Presence/TypingIndicator';
import { findMentionTrigger, insertMention } from '../../helpers/chatMention';
import {
  ChatMentionPicker,
  type ChatMentionPickerHandle,
} from './ChatMentionPicker';
import {
  useSealedMessage,
  type SealedState,
} from '../Conversation/sealedMessages';

const CHAT_PAGE_SIZE = 50;

export interface ChatViewProps {
  messages: string[];
  loading: boolean;
  /** Messages older than the ones listed; shows a "load older" row when > 0. */
  olderCount?: number;
  onLoadOlder?: () => void;
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
  olderCount = 0,
  onLoadOlder,
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
  const [scrollToBottomTrigger, setScrollToBottomTrigger] = useState(0);
  const [caret, setCaret] = useState(0);
  // Start index of an `@` token closed with Escape; reopens on a new `@`.
  const [dismissedAt, setDismissedAt] = useState<number>();
  const pickerRef = useRef<ChatMentionPickerHandle>(null);

  const { typers, notifyTyping, stopTyping } = useTypingPresence(threadSubject);

  // Messages that arrive once the chat is on screen grow into place from
  // the bottom, where the "is typing" line was; the ones already there when
  // it opened just appear. A short wait after loading lets a list that loads
  // in a few batches count as already there.
  const [settled, setSettled] = useState(false);

  useEffect(() => {
    if (messagesLoading || settled) return;
    const timer = setTimeout(() => setSettled(true), 400);

    return () => clearTimeout(timer);
  }, [messagesLoading, settled]);

  const disableSend = newMessageVal.length === 0;

  // Older messages are added ABOVE the ones being read. Keep the message that
  // was at the top where it was (browsers without scroll anchoring would
  // otherwise jump to the new top).
  const olderRowRef = useRef<HTMLButtonElement>(null);
  const anchorRef = useRef<{ el: Element; top: number } | null>(null);

  const handleLoadOlder = () => {
    const el = olderRowRef.current?.nextElementSibling;

    if (el) anchorRef.current = { el, top: el.getBoundingClientRect().top };
    onLoadOlder?.();
  };

  useLayoutEffect(() => {
    const anchor = anchorRef.current;

    if (!anchor || !anchor.el.isConnected) return;
    anchorRef.current = null;
    const delta = anchor.el.getBoundingClientRect().top - anchor.top;

    if (delta === 0) return;
    let scroller: HTMLElement | null = anchor.el.parentElement;

    while (scroller && scroller.scrollHeight <= scroller.clientHeight) {
      scroller = scroller.parentElement;
    }

    if (scroller) scroller.scrollTop += delta;
  }, [messages]);

  const sendMessage = async (e?: React.SyntheticEvent) => {
    e?.preventDefault();

    if (disableSend) {
      return;
    }

    const messageBackup = newMessageVal;
    const replyBackup = isReplyTo;

    try {
      setScrollToBottomTrigger(prev => prev + 1);
      setNewMessage('');
      // The message shows up before the server has answered, so the reply
      // state is cleared with the text: the next message is a plain one.
      setReplyTo(undefined);
      stopTyping();
      await onSend(messageBackup, replyBackup);
    } catch (err) {
      setNewMessage(messageBackup);
      setReplyTo(replyBackup);
      toast.error(err.message);
    }
  };

  const mentionTrigger = findMentionTrigger(newMessageVal, caret);
  const openTrigger =
    mentionTrigger && mentionTrigger.start !== dismissedAt
      ? mentionTrigger
      : undefined;

  const handleSelectMention = (subject: string, label: string) => {
    if (!openTrigger) return;
    const result = insertMention(newMessageVal, openTrigger, subject, label);

    setNewMessage(result.text);
    setCaret(result.caret);
    // Put the caret behind the inserted mention once React has rendered it.
    requestAnimationFrame(() => {
      inputRef.current?.focus();
      inputRef.current?.setSelectionRange(result.caret, result.caret);
    });
    notifyTyping();
  };

  const syncCaret: React.ReactEventHandler<HTMLTextAreaElement> = e => {
    setCaret(e.currentTarget.selectionStart);
  };

  const handleKeyDown: React.KeyboardEventHandler<HTMLTextAreaElement> = e => {
    if (openTrigger) {
      if (e.key === 'Escape') {
        e.preventDefault();
        setDismissedAt(openTrigger.start);

        return;
      }

      if (
        ['ArrowUp', 'ArrowDown', 'Enter', 'Tab'].includes(e.key) &&
        pickerRef.current?.onKeyDown(e.key === 'Tab' ? 'Enter' : e.key)
      ) {
        e.preventDefault();

        return;
      }
    }

    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    } else if (e.key === 'Escape') {
      inputRef.current?.blur();
    }
  };

  // The React Compiler memoizes this; a manual useCallback over `inputRef`
  // could no longer be preserved once the input's height is read from it.
  const handleReply = (subject: string) => {
    setReplyTo(subject);
    inputRef.current?.focus();
  };

  const handleChangeMessageText: React.ChangeEventHandler<
    HTMLTextAreaElement
  > = e => {
    setNewMessage(e.target.value);
    setCaret(e.target.selectionStart);

    if (e.target.value === '') {
      stopTyping();

      return;
    }

    notifyTyping();
  };

  // Grow the input with its text, to exactly the text's height. Counting
  // rows at an assumed 30px each left a line-height of 24px short: a few
  // lines in, the input could be scrolled by a line's worth. Runs on every
  // change of the value, so it also shrinks back after sending.
  useLayoutEffect(() => {
    const input = inputRef.current;
    if (!input) return;
    input.style.height = 'auto';
    input.style.height = `${input.scrollHeight + input.offsetHeight - input.clientHeight}px`;
  }, [newMessageVal, inputRef]);

  return (
    <ViewWrapper>
      <ScrollAreaWrapper>
        <ChatMessagesContainer
          enableAutoScroll
          scrollToBottomTrigger={scrollToBottomTrigger}
          fullView={noContainerPadding}
        >
          {messagesLoading ? (
            <Spinner centered />
          ) : messages.length === 0 ? (
            <EmptyChatState>
              <FaMessage />
              <p>No messages yet</p>
              <span>Be the first to say something</span>
            </EmptyChatState>
          ) : (
            <>
              {olderCount > 0 && (
                <LoadOlder
                  ref={olderRowRef}
                  type='button'
                  onClick={handleLoadOlder}
                >
                  {`Show older messages (${olderCount})`}
                </LoadOlder>
              )}
              {messages.map(message => (
                <Appear key={message} animate={settled}>
                  <Message subject={message} setReplyTo={handleReply} />
                </Appear>
              ))}
            </>
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
      <ComposerWrapper>
        {openTrigger && (
          <ChatMentionPicker
            trigger={openTrigger}
            onSelect={handleSelectMention}
            handleRef={pickerRef}
          />
        )}
        <MessageForm onSubmit={sendMessage} $viewTransition={viewTransition}>
          <MessageInput
            aria-label='Chat input'
            rows={1}
            ref={inputRef}
            autoFocus
            value={newMessageVal}
            onChange={handleChangeMessageText}
            onKeyDown={handleKeyDown}
            onKeyUp={syncCaret}
            onClick={syncCaret}
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
      </ComposerWrapper>
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
  const { messages, loading, olderCount, loadOlder, send } = useChatMessages(
    resource.subject,
  );

  const handleSend = (text: string, replyTo?: string) =>
    send(text, { parent: resource.subject, replyTo });

  return (
    <ChatView
      messages={messages}
      loading={loading}
      olderCount={olderCount}
      onLoadOlder={loadOlder}
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

/**
 * Posts a message to a chat as an entry of its log (`planning/chat-log.md`);
 * no `Message` resource is made. Follow events (`extraClasses` with
 * FollowEvent) become entries of kind FollowEvent.
 */
export async function sendChatMessage(
  store: Store,
  { parent, text, about, replyTo, extraClasses }: SendChatMessageOptions,
) {
  await sendLogEntry(store, {
    parent,
    text,
    about,
    replyTo,
    kind: extraClasses?.includes(dataBrowser.classes.followEvent)
      ? dataBrowser.classes.followEvent
      : undefined,
  });
}

type SetReplyToType = (subject: string) => unknown;

/** What a sealed message shows: its text, nothing while it is being opened,
 *  or why it can't be read. */
function sealedText(state: SealedState & { sealed: true }): string {
  if (state.payload === undefined) {
    return '';
  }

  return (
    state.payload?.text ??
    'This message was sent before you joined, or it was changed, so it can not be opened.'
  );
}

interface MessageProps {
  subject: string;
  /** Is called when the `reply` button is pressed */
  setReplyTo: SetReplyToType;
}

/** How many characters are shown at max by default in a message */
const MESSAGE_MAX_LEN = 500;

/** Single message shown in a ChatRoom: an old Message resource or a log entry. */
const Message = memo(function Message({ subject, setReplyTo }: MessageProps) {
  return parseEntryId(subject) ? (
    <LogMessage id={subject} setReplyTo={setReplyTo} />
  ) : (
    <ResourceMessage subject={subject} setReplyTo={setReplyTo} />
  );
});

interface MessageViewProps {
  /** Identifies the message in the page (RDFa `about`). */
  about: string;
  text: string;
  createdAt: Date | undefined;
  createdBy: string | undefined;
  replyTo: string | undefined;
  /** The key of a log entry, to scroll to a link to it. */
  entryKey?: string;
  edited?: boolean;
  /** Replaces the text with an editor. Only for messages the viewer may change. */
  editing?: React.ReactNode;
  onEdit?: () => void;
  onDelete?: () => void;
  onReply: () => void;
  onCopyUrl: () => void;
}

/** The look of one message: avatar, author and time, actions and the text. */
function MessageView({
  about,
  text,
  createdAt,
  createdBy,
  replyTo,
  entryKey,
  edited,
  editing,
  onEdit,
  onDelete,
  onReply,
  onCopyUrl,
}: MessageViewProps) {
  function handleCopyText() {
    navigator.clipboard.writeText(text || '');
    toast.success('Copied message text to clipboard');
  }

  return (
    <MessageComponent about={about} data-entry-key={entryKey}>
      {createdBy ? (
        <PresenceAvatarMenu
          agentSubject={createdBy}
          size='1.8rem'
          chip={false}
        />
      ) : (
        <AvatarSpacer />
      )}
      <MessageBody>
        <MessageDetails>
          <MessageMeta createdAt={createdAt} createdBy={createdBy} />
          {edited && <span>(edited)</span>}
          {replyTo && <MessageLine subject={replyTo} />}
          <MessageActions>
            {onEdit && (
              <IconButton onClick={onEdit} title='Edit message'>
                <FaPencil />
              </IconButton>
            )}
            {onDelete && (
              <IconButton onClick={onDelete} title='Delete message'>
                <FaTrash />
              </IconButton>
            )}
            <IconButton onClick={onReply} title='Reply to this message'>
              <FaReply />
            </IconButton>
            <IconButton onClick={onCopyUrl} title='Copy link to this message'>
              <FaLink />
            </IconButton>
            <IconButton onClick={handleCopyText} title='Copy message text'>
              <FaCopy />
            </IconButton>
          </MessageActions>
        </MessageDetails>
        {/* markExternalLinks routes links through AtomicLink: subject links
            navigate in-app instead of triggering a full page load. */}
        {editing ?? (
          <Markdown
            text={text || ''}
            maxLength={MESSAGE_MAX_LEN}
            markExternalLinks
          />
        )}
      </MessageBody>
    </MessageComponent>
  );
}

/** A message that is a resource of its own. */
function ResourceMessage({ subject, setReplyTo }: MessageProps) {
  const resource = useResource(subject);
  const sealed = useSealedMessage(subject);
  const [plainDescription] = useString(resource, core.properties.description);
  const description = sealed.sealed ? sealedText(sealed) : plainDescription;
  const [isA] = useArray(resource, core.properties.isA);
  const isFollowEvent = isA.includes(dataBrowser.classes.followEvent);
  // Creation date + creator come from the genesis change in the resource's own
  // Loro oplog (materialized into propvals) — no commit fetch, so they survive
  // a refresh. The commit subject is intentionally NOT passed.
  const createdAt = useCreatedAt(resource);
  const createdBy = useMessageSpeaker(resource);
  const [plainReplyTo] = useSubject(resource, dataBrowser.properties.replyTo);
  const replyTo = sealed.sealed ? sealed.payload?.replyTo : plainReplyTo;
  const navigate = useNavigateWithTransition();
  // A sealed message has no plain text to edit in the form.
  const canWrite = useCanWrite(resource) && !sealed.sealed;

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

  return (
    <MessageView
      about={subject}
      text={description ?? ''}
      createdAt={createdAt}
      createdBy={createdBy}
      replyTo={replyTo}
      onEdit={canWrite ? () => navigate(editURL(subject)) : undefined}
      onReply={() => setReplyTo(subject)}
      onCopyUrl={handleCopyUrl}
    />
  );
}

/** A message that is an entry in a ChatLog page. */
function LogMessage({
  id,
  setReplyTo,
}: {
  id: string;
  setReplyTo: SetReplyToType;
}) {
  const store = useStore();
  const [agent] = useCurrentAgent();
  const { entry, key } = useChatLogEntry(id);
  const sealedState = useSealedMessage(id);
  const [editingText, setEditingText] = useState<string>();

  if (!entry || !key) {
    return <MessageComponent about={id} />;
  }

  // A direct message: the entry holds the sealed payload (`s`), opened by the
  // conversation page. There is no plain text to edit.
  const isSealed = typeof entry.s === 'string';
  const text =
    isSealed && sealedState.sealed ? sealedText(sealedState) : entry.t;
  const replyTo =
    isSealed && sealedState.sealed ? sealedState.payload?.replyTo : entry.r;

  if (isFollowEntry(entry)) {
    return (
      <FollowEventMessage
        description={entry.t}
        createdAt={new Date(entry.c)}
        createdBy={entry.a}
      />
    );
  }

  // The server only lets an author change their own entries; moderators can
  // too, but own messages are what the buttons are for.
  const isMine = !!agent && entry.a === agent.subject;

  function handleCopyUrl() {
    navigator.clipboard.writeText(id);
    toast.success('Copied message URL to clipboard');
  }

  async function saveEdit() {
    if (editingText === undefined) return;

    try {
      await editLogEntry(store, id, editingText);
      setEditingText(undefined);
    } catch (err) {
      toast.error(err.message);
    }
  }

  async function handleDelete() {
    if (!window.confirm('Delete this message?')) return;

    try {
      await deleteLogEntry(store, id);
    } catch (err) {
      toast.error(err.message);
    }
  }

  return (
    <MessageView
      about={id}
      entryKey={key}
      text={text}
      createdAt={new Date(entry.c)}
      createdBy={entry.a}
      replyTo={replyTo}
      edited={entry.e !== undefined}
      editing={
        editingText === undefined ? undefined : (
          <EditMessage
            aria-label='Edit message text'
            value={editingText}
            autoFocus
            onChange={e => setEditingText(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                void saveEdit();
              } else if (e.key === 'Escape') {
                setEditingText(undefined);
              }
            }}
          />
        )
      }
      onEdit={isMine && !isSealed ? () => setEditingText(entry.t) : undefined}
      onDelete={isMine ? handleDelete : undefined}
      onReply={() => setReplyTo(id)}
      onCopyUrl={handleCopyUrl}
    />
  );
}

const EditMessage = styled.textarea`
  width: 100%;
  min-height: 3rem;
  padding: ${p => p.theme.size(2)};
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  background: ${p => p.theme.colors.bg};
  color: ${p => p.theme.colors.text};
  font: inherit;
  resize: vertical;
`;

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
  return parseEntryId(subject) ? (
    <EntryMessageLine subject={subject} />
  ) : (
    <ResourceMessageLine subject={subject} />
  );
}

function MessageLineView({
  subject,
  ready,
  author,
  text,
}: {
  subject: string;
  ready: boolean;
  author: string | undefined;
  text: string | undefined;
}) {
  if (!ready) {
    return <MessageLineStyled>loading...</MessageLineStyled>;
  }

  // truncate and add ellipsis
  const truncated = text?.substring(0, MESSAGE_LINE_MAX_LEN);
  const ellipsis = text && text.length > MESSAGE_LINE_MAX_LEN ? '...' : '';

  return (
    <MessageLineStyled>
      <span>to </span>
      {author && <ResourceInline subject={author} />}
      <AtomicLink subject={subject}>{`: ${truncated}${ellipsis}`}</AtomicLink>
    </MessageLineStyled>
  );
}

function ResourceMessageLine({ subject }: MessageLineProps) {
  const { resource, ready } = useResourceSnapshot(subject);
  const sealed = useSealedMessage(subject);
  const [plainDescription] = useString(resource, core.properties.description);
  const description = sealed.sealed ? sealedText(sealed) : plainDescription;
  // Author from the resource's own genesis metadata (createdBy) — not a commit
  // fetch, so it survives a refresh.
  const author = useMessageSpeaker(resource);

  return (
    <MessageLineView
      subject={subject}
      ready={ready}
      author={author}
      text={description}
    />
  );
}

function EntryMessageLine({ subject: id }: MessageLineProps) {
  const { entry } = useChatLogEntry(id);
  const sealed = useSealedMessage(id);
  const text =
    typeof entry?.s === 'string' && sealed.sealed
      ? sealedText(sealed)
      : entry?.t;

  return (
    <MessageLineView
      subject={id}
      ready={!!entry}
      author={entry?.a}
      text={text}
    />
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

/** Grows a message into place if it arrived while the chat was open. Whether
 *  to animate is fixed at mount, so messages already listed never replay it. */
function Appear({
  animate,
  children,
}: {
  animate: boolean;
  children: React.ReactNode;
}) {
  const [grow] = useState(animate);

  return <AppearWrapper $grow={grow}>{children}</AppearWrapper>;
}

const growIn = keyframes`
  from {
    opacity: 0;
    transform: translateY(0.75rem) scale(0.96);
  }
`;

const AppearWrapper = styled.div<{ $grow: boolean }>`
  ${p =>
    p.$grow &&
    css`
      transform-origin: left bottom;
      animation: ${growIn} 260ms cubic-bezier(0.2, 0.7, 0.2, 1) both;

      @media (prefers-reduced-motion: reduce) {
        animation: none;
      }
    `}
`;

const MessageComponent = styled.div`
  display: flex;
  align-items: flex-start;
  /* Enough room that the avatar's hover ring never touches the body chip. */
  gap: 0.75rem;
  padding-block: 0.1rem;
  /* Room for the body chip's negative right margin. Without it the row is
   * 0.5rem wider than the scroll viewport and the chat scrolls sideways. */
  padding-inline-end: 0.5rem;

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
  box-sizing: border-box;
  resize: none;
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

/** Anchors the mention picker to the composer. */
const ComposerWrapper = styled.div`
  position: relative;
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

const LoadOlder = styled.button`
  align-self: center;
  margin-block: 0.25rem 0.5rem;
  padding: 0.25rem 0.75rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  background: none;
  color: ${p => p.theme.colors.textLight};
  font-size: 0.8rem;
  cursor: pointer;

  &:hover {
    background: ${p => p.theme.colors.bg1};
    color: ${p => p.theme.colors.text};
  }
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
const ONLY_SEALED_MESSAGES = [
  { property: core.properties.isA, value: conversations.classes.sealedMessage },
];

/** Every resource is stamped with the drive it belongs to at genesis, which
 *  for a resource shared from elsewhere is the OWNER's drive, not the
 *  viewer's. See `Resource.save` in @tomic/lib. */
const DRIVE_PROP = 'https://atomicdata.dev/properties/drive';

interface ChatTail {
  total: number;
  messages: string[];
}

function readTail(key: string): ChatTail | undefined {
  try {
    const raw = localStorage.getItem(key);

    return raw ? (JSON.parse(raw) as ChatTail) : undefined;
  } catch {
    return undefined;
  }
}

function writeTail(key: string, tail: ChatTail) {
  try {
    localStorage.setItem(key, JSON.stringify(tail));
  } catch {
    // Storage full or blocked: the chat just opens the slower way.
  }
}

/** What the message list shows: the newest messages and how many are older. */
interface ChatWindow {
  messages: string[];
  olderCount: number;
  /** Pages whose entries are in `messages`; watched for changes. */
  loadedPages: string[];
}

const NO_PAGES: string[] = [];

/**
 * Fetches the messages of a chat or a comment thread, sorted by createdAt
 * ascending (oldest first) with pagination. ChatRooms link their messages via
 * `parent` (the default); comment threads via `about`.
 *
 * A message is either a `Message` resource (what older versions wrote, and
 * follow events still are) or an entry in a ChatLog page (what new messages
 * are). The list holds the subject of the first and the entry id
 * (`<page subject>#<entry key>`) of the second, merged by time.
 */
export function useChatMessages(
  subject: string,
  property: string = core.properties.parent,
  /** A Conversation's messages are SealedMessages. */
  sealed = false,
) {
  const store = useStore();
  // The newest messages seen last time this chat was open, so a reopened chat
  // fills at once from the local database while the real list (server sorted,
  // after the connection is up) is on its way.
  const tailKey = `chat-tail:${subject}:${property}`;
  const [remembered] = useState(() => readTail(tailKey));
  const [view, setView] = useState<ChatWindow>(() => ({
    messages: remembered?.messages ?? [],
    olderCount: remembered
      ? Math.max(0, remembered.total - remembered.messages.length)
      : 0,
    loadedPages: NO_PAGES,
  }));
  // How many of the NEWEST messages are listed. A busy chat can hold
  // thousands; listing (and rendering) them all made opening it a stall and
  // an unbounded DOM. Older ones load a page at a time on request.
  const [visible, setVisible] = useState(CHAT_PAGE_SIZE);

  // Scope the query to the drive the THREAD lives on, not the viewer's active
  // one. A guest opening a chatroom shared from another drive has their own
  // drive selected, and the query index is keyed by drive, so the default
  // scope looked for the messages in the wrong place and always answered
  // zero. Until the thread resource has loaded its stamp there is nothing
  // better than the default, so leave it alone.
  const thread = useResource(subject);
  // A Conversation is a drive itself, so it carries no stamp of its own.
  const threadDrive =
    thread.get(DRIVE_PROP) ??
    (thread.hasClasses(server.classes.drive) ? subject : undefined);
  const drive = typeof threadDrive === 'string' ? threadDrive : undefined;

  const { collection, ready, invalidateCollection } = useCollection(
    {
      property,
      value: subject,
      filters: sealed ? ONLY_SEALED_MESSAGES : ONLY_MESSAGES,
      sort_by: commits.properties.createdAt,
      sort_desc: false,
      drive,
    },
    { pageSize: CHAT_PAGE_SIZE, preferServer: true },
  );
  const logPages = useChatLogPages(property, subject, drive);
  // Entries are not properties: an entry from another tab or agent, or one
  // added here, only shows up through this number changing.
  const revision = useChatLogRevision(view.loadedPages);
  const { pages, ready: pagesReady } = logPages;

  useEffect(() => {
    let cancelled = false;

    const extractMembers = async () => {
      await collection.waitForReady();
      const count = collection.totalMembers;
      const members: string[] = [];

      try {
        // Re-read the count each step: the collection can refresh with fewer
        // members while we await, and an index past the end throws.
        for (
          let i = Math.max(0, count - visible);
          i < collection.totalMembers;
          i++
        ) {
          const member = await collection.getMemberWithIndex(i);

          if (member) {
            members.push(member);
          }
        }
      } catch {
        // The collection changed under us; its next refresh extracts again.
        return;
      }

      let next: ChatWindow = {
        messages: members,
        olderCount: Math.max(0, count - members.length),
        loadedPages: NO_PAGES,
      };

      if (pages.length > 0) {
        const old: Timed[] = await Promise.all(
          members.map(async id => ({
            id,
            at: (await store.getResource(id)).getCreatedAt() ?? 0,
          })),
        );
        const entryKeys = new Set<string>();
        const log: Timed[] = [];
        const loadedPages: string[] = [];
        let index = pages.length - 1;

        // Newest pages first, as many as it takes to fill the window.
        while (index >= 0 && log.length < visible) {
          const current = pages[index];
          index--;
          const page = await store.getResource(current);

          loadedPages.push(current);

          if (page.error) continue;

          for (const { key, entry } of page.listChatLogEntries()) {
            // One key on two pages (two peers migrated the same message) is
            // one message.
            if (entryKeys.has(key)) continue;
            entryKeys.add(key);
            log.push({ id: toEntryId(current, key), at: entry.c });
          }
        }

        // An old Message that already has its entry is a stale copy.
        const { shown, hidden } = hideMigrated(old, entryKeys);

        const merged = windowChat({
          old: shown,
          oldTotal: count - hidden,
          log,
          unloadedPages: index + 1,
          visible,
        });
        next = {
          messages: merged.ids,
          olderCount: merged.olderCount,
          loadedPages,
        };
      }

      if (cancelled) return;

      setView(previous =>
        previous.messages.length === next.messages.length &&
        previous.olderCount === next.olderCount &&
        previous.messages.every((id, i) => id === next.messages[i]) &&
        previous.loadedPages.length === next.loadedPages.length &&
        previous.loadedPages.every((page, i) => page === next.loadedPages[i])
          ? previous
          : next,
      );

      // An empty chat is remembered too, so reopening it does not flash the
      // loader every time while the server answers "no messages".
      if (visible === CHAT_PAGE_SIZE && pagesReady) {
        writeTail(tailKey, {
          total: next.messages.length + next.olderCount,
          messages: next.messages,
        });
      }
    };

    void extractMembers();

    return () => {
      cancelled = true;
    };
  }, [collection, visible, tailKey, store, pages, pagesReady, revision]);

  // `useCollection` (used internally by this hook) routes
  // `ResourceManuallyCreated` through `applyResourceChange` for an
  // optimistic append — sent follow events appear instantly without a
  // server round-trip.

  const send = async (
    text: string,
    {
      parent,
      replyTo,
    }: {
      /** Rights anchor of the log: the ChatRoom, or the drive's Comments folder. */
      parent: string;
      replyTo?: string;
    },
  ) => {
    const known = pagesReady
      ? pages
      : await queryPages(store, property, subject, drive);

    await appendToChatLog(store, {
      parent,
      about: property === dataBrowser.properties.about ? subject : undefined,
      text,
      replyTo,
      pages: known,
      scope: scopeKey(property, subject),
    });
    logPages.refresh();
  };

  return {
    messages: view.messages,
    loading:
      (!ready || !pagesReady) && view.messages.length === 0 && !remembered,
    invalidate: async () => {
      if (sealed) await invalidateCollection();
      logPages.refresh();
    },
    /** Messages that exist but are not listed yet (older than the window). */
    olderCount: view.olderCount,
    loadOlder: () => setVisible(v => v + CHAT_PAGE_SIZE),
    /** Appends a message to the chat's log: its newest page, or a new one. */
    send,
  };
}
