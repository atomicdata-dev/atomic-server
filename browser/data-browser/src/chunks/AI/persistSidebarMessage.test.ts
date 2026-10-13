import { describe, expect, it, vi, beforeEach } from 'vitest';
import type { AtomicUIMessage } from './types';
import type { PersistSidebarMessageArgs } from './persistSidebarMessage';

const saved: string[] = [];
const serverPersisted: string[] = [];
const queues = new WeakMap<object, Promise<unknown>>();

vi.mock('./chatConversionUtils', () => ({
  addMessageToChatResource: vi.fn(async (added, chat, _store, opts) => {
    if (opts?.saveChat) saved.push(chat.subject);

    return { subject: `message-${added.role}`, props: { parts: [] } };
  }),
  persistMessageResourceToServer: vi.fn(
    async (resource: { subject: string }) => {
      serverPersisted.push(resource.subject);
    },
  ),
  // Same contract as the real one: work for one chat runs strictly in order.
  queueChatWrite: vi.fn((chat: object, work: () => Promise<unknown>) => {
    const next = (queues.get(chat) ?? Promise.resolve())
      .catch(() => {})
      .then(work);
    queues.set(chat, next);

    return next;
  }),
}));

const { persistSidebarMessage } = await import('./persistSidebarMessage');
const { addMessageToChatResource } = await import('./chatConversionUtils');

const NAME = 'https://atomicdata.dev/properties/name';

function fakeChat(name = 'Untitled Chat') {
  const props: Record<string, unknown> = { [NAME]: name };

  return {
    subject: 'chat-1',
    get: (property: string) => props[property],
    set: async (property: string, value: unknown) => {
      props[property] = value;
    },
    save: async () => {
      saved.push('chat-1');
    },
    props,
  };
}

function message(role: 'user' | 'assistant'): AtomicUIMessage {
  return { id: role, role, parts: [] } as unknown as AtomicUIMessage;
}

/** Everything the function needs, with the pieces a test cares about swappable. */
function args(
  chat: ReturnType<typeof fakeChat>,
  overrides: Record<string, unknown> = {},
): PersistSidebarMessageArgs {
  return {
    store: {},
    getOrCreateDraftChatResource: async () => chat,
    isChatSavedRef: { current: false },
    titlePromiseRef: { current: undefined },
    setMessageToResourceMap: () => undefined,
    messageToResourceMapRef: { current: new Map() },
    setIsChatSaved: () => undefined,
    shouldGenerateTitles: true,
    generateTitle: async () => ({ title: 'A good title', emoji: '\u{1F4A1}' }),
    ...overrides,
  } as unknown as PersistSidebarMessageArgs;
}

beforeEach(() => {
  saved.length = 0;
  serverPersisted.length = 0;
});

/**
 * A sidebar chat used to live only in memory until the assistant's reply
 * finished. Anything that ended the page in that window — a hot reload, a
 * crash, a closed tab — took the question, the half-written answer and the
 * chat resource with it, and because no resource had ever been created the
 * conversation could not even be found afterwards.
 *
 * These tests are about the write, not the screen. The screen was never the
 * problem: it showed the chat perfectly while nothing was being saved.
 */
describe('persistSidebarMessage', () => {
  it('saves the chat when the question is asked, not when it is answered', async () => {
    const chat = fakeChat();
    const isChatSavedRef = { current: false };

    await persistSidebarMessage({
      ...args(chat, { isChatSavedRef }),
      message: message('user'),
      newMessages: [message('user')],
    });

    // Before any reply exists. This is the whole fix: the model may take
    // minutes, and until now that was minutes of holding the only copy in a
    // JavaScript variable.
    // The React setter is deliberately deferred/no-op in this fixture.
    expect(serverPersisted).toContain('message-user');
    expect(saved).toContain('chat-1');
    expect(isChatSavedRef.current).toBe(true);
  });

  it('pushes the messages to the server before the chat points at them', async () => {
    const chat = fakeChat();
    const pending = new Map([
      [message('user'), { subject: 'message-user', props: { parts: [] } }],
    ]);

    await persistSidebarMessage({
      ...args(chat, { messageToResourceMapRef: { current: pending } }),
      message: message('user'),
      newMessages: [message('user')],
    });

    // A chat that references children the server has not seen is a commit that
    // fails validation and gets dropped.
    expect(serverPersisted).toContain('message-user');
  });

  it('still names the chat, even though it was saved a message earlier', async () => {
    // The trap in this change: titling used to be gated on the chat NOT being
    // saved yet. Finalising on the user's message makes that condition false
    // by the time the reply lands, so a naive fix leaves every chat called
    // "Untitled Chat" for ever.
    const chat = fakeChat();

    await persistSidebarMessage({
      ...args(chat, { isChatSavedRef: { current: true } }),
      message: message('assistant'),
      newMessages: [message('user'), message('assistant')],
    });

    expect(chat.get(NAME)).toBe('A good title');
  });

  it('names the chat as soon as the question is asked, with an emoji', async () => {
    // Chats whose reply never arrived used to stay "Untitled Chat" for ever,
    // which filled the sidebar with anonymous entries.
    const chat = fakeChat();

    await persistSidebarMessage({
      ...args(chat),
      message: message('user'),
      newMessages: [message('user')],
    });

    await vi.waitFor(() => expect(chat.get(NAME)).toBe('A good title'));
    expect(chat.get('https://atomicdata.dev/properties/emoji')).toBe(
      '\u{1F4A1}',
    );
  });

  it('sends a reply whose chat stopped being a draft while the write was queued', async () => {
    // The checkpoint carrying the last chunk of a streamed reply is built
    // while the chat is still a draft, so it is created local-only, and its
    // write can resolve after the user's message has finalized the chat. It
    // then misses the sweep that runs on the user's message, and nothing else
    // ever comes back for it: not in the outbox, no dirty flag, so no drain
    // retries it and the tab reports itself fully synced while that chunk
    // exists on screen and nowhere else.
    const chat = fakeChat();
    const isChatSavedRef = { current: false };

    vi.mocked(addMessageToChatResource).mockImplementationOnce(async added => {
      // The finalization lands while this write is in flight.
      isChatSavedRef.current = true;

      return {
        subject: `message-${added.role}`,
        props: { parts: [] },
      } as never;
    });

    await persistSidebarMessage({
      ...args(chat, { isChatSavedRef }),
      message: message('assistant'),
      newMessages: [message('user'), message('assistant')],
    });

    expect(serverPersisted).toContain('message-assistant');
  });

  it('does not put a still-draft chat on the server just to name it', async () => {
    // A title can resolve before the finalization has pushed the messages.
    // Saving the chat then publishes it already pointing at children the
    // server has not seen, and whoever opens it in that window gets
    // "Resource not found" where the reply should be. The name still lands on
    // the resource; the finalization's own save carries it.
    // No question in the conversation: still the empty draft, which only the
    // user's first message turns into a chat.
    const chat = fakeChat();

    await persistSidebarMessage({
      ...args(chat, { isChatSavedRef: { current: false } }),
      message: message('assistant'),
      newMessages: [message('assistant'), message('assistant')],
    });

    expect(chat.get(NAME)).toBe('A good title');
    expect(saved).not.toContain('chat-1');
  });

  it('leaves a chat that already has a name alone', async () => {
    const chat = fakeChat('Something the user typed');

    await persistSidebarMessage({
      ...args(chat, { isChatSavedRef: { current: true } }),
      message: message('assistant'),
      newMessages: [message('user'), message('assistant')],
    });

    expect(chat.get(NAME)).toBe('Something the user typed');
  });

  it('does not name a chat when the user has titles switched off', async () => {
    const chat = fakeChat();

    await persistSidebarMessage({
      ...args(chat, {
        isChatSavedRef: { current: true },
        shouldGenerateTitles: false,
      }),
      message: message('assistant'),
      newMessages: [message('user'), message('assistant')],
    });

    expect(chat.get(NAME)).toBe('Untitled Chat');
  });

  it('finalizes on the reply when saving the question failed', async () => {
    // A save can fail once (a dropped connection, a save that is only queued
    // in the outbox). The chat then stays a draft, and every reply after it
    // used to be built local-only: only another question swept it up, so a
    // chat whose last turn was an answer lived on one device alone.
    const chat = fakeChat();
    const isChatSavedRef = { current: false };
    const failOnce = vi.fn(async () => {
      throw new Error('network');
    });
    const save = chat.save;

    chat.save = failOnce;
    const user = message('user');
    const base = args(chat, { isChatSavedRef, shouldGenerateTitles: false });
    const pending = new Map();

    await expect(
      persistSidebarMessage({
        ...base,
        messageToResourceMapRef: { current: pending },
        message: user,
        newMessages: [user],
      }),
    ).rejects.toThrow('network');
    expect(isChatSavedRef.current).toBe(false);

    chat.save = save;
    pending.set(user, { subject: 'message-user', props: { parts: [] } });
    serverPersisted.length = 0;
    const reply = message('assistant');

    await persistSidebarMessage({
      ...base,
      messageToResourceMapRef: { current: pending },
      message: reply,
      newMessages: [user, reply],
    });

    expect(isChatSavedRef.current).toBe(true);
    expect(serverPersisted).toContain('message-user');
    expect(saved).toContain('chat-1');
  });
});
