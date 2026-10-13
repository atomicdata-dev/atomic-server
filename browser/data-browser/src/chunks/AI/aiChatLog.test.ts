import { describe, expect, it } from 'vitest';
import type { Resource, Store, ChatLogEntry } from '@tomic/react';
import { migratedEntryKey } from '@tomic/react';
import type { AtomicUIMessage } from './types';
import { entryToMessage, messageToEntry } from './aiChatEntries';
import {
  addMessageToChatResource,
  loadChatMessages,
  mergeByTime,
  removeFollowingMessagesFromChatResource,
  removeMessageFromChatResource,
  type AiMessageRef,
} from './chatConversionUtils';

const AGENT = 'did:ad:agent:alice';

class FakePage {
  public error: Error | undefined;
  public saves = 0;
  public entries = new Map<string, ChatLogEntry>();

  public constructor(public subject: string) {}

  public countChatLogEntries() {
    return this.entries.size;
  }
  public getCreatedAt() {
    return 1;
  }
  public putChatLogEntry(key: string, entry: ChatLogEntry) {
    this.entries.set(key, entry);
  }
  public getChatLogEntry(key: string) {
    return this.entries.get(key);
  }
  public removeChatLogEntry(key: string) {
    this.entries.delete(key);
  }
  public listChatLogEntries() {
    return [...this.entries.keys()]
      .sort()
      .map(key => ({ key, entry: this.entries.get(key)! }));
  }
  public async save() {
    this.saves++;
  }
}

function setup(chatSubject = 'did:ad:chat1') {
  const pages = new Map<string, FakePage>();
  const store = {
    getAgent: () => ({ subject: AGENT }),
    normalizeSubject: (s: string) => s,
    getResource: async (subject: string) => pages.get(subject),
    getResources: async (subjects: string[]) =>
      subjects.map(s => ({ subject: s, getCreatedAt: () => 5, props: {} })),
    newResource: async () => {
      const page = new FakePage(`did:ad:page${pages.size + 1}`);
      pages.set(page.subject, page);

      return page;
    },
    notifyResourceManuallyCreated: async () => undefined,
  } as unknown as Store;
  const chat = {
    subject: chatSubject,
    new: true,
    props: {} as Record<string, unknown>,
    get: () => undefined,
  } as unknown as Resource;

  return { store, chat, pages };
}

const user = (id: string, text: string): AtomicUIMessage => ({
  id,
  role: 'user',
  parts: [{ type: 'text', text }],
});

const assistant = (id: string, text: string): AtomicUIMessage => ({
  id,
  role: 'assistant',
  parts: [
    { type: 'step-start' },
    { type: 'reasoning', text: 'hm' },
    {
      type: 'tool-search',
      toolCallId: 'c1',
      state: 'output-available',
      input: { q: 'x' },
      output: { rows: [1, 2] },
    },
    { type: 'text', text },
  ],
});

describe('message <-> entry', () => {
  it('round-trips parts, tool calls, context and errors', () => {
    const message: AtomicUIMessage = {
      ...assistant('a', 'hello'),
      metadata: { error: 'Provider failed' },
    };
    const entry = messageToEntry(message, AGENT, 42);
    expect(entry).toMatchObject({ a: AGENT, c: 42, role: 'assistant', t: '' });
    expect(entry.err).toBe('Provider failed');

    const back = entryToMessage('page#2a-00000000', entry)!;
    expect(back.id).toBe('page#2a-00000000');
    expect(back.parts.map(p => p.type)).toEqual([
      'reasoning',
      'tool-search',
      'text',
    ]);
    expect(back.parts[1]).toMatchObject({
      state: 'output-available',
      output: { rows: [1, 2] },
    });
    expect(back.metadata?.error).toBe('Provider failed');
  });

  it('keeps provided context of a user message and drops skills', () => {
    const entry = messageToEntry(
      {
        ...user('u', 'q'),
        metadata: {
          serverContext: 'server says',
          userContext: [
            { type: 'atomic-resource', id: '1', subject: 'did:ad:x' },
            { type: 'skill', id: '2', name: 'writing' },
          ],
        },
      },
      AGENT,
      1,
    );
    const back = entryToMessage('id', entry)!;
    expect(back.metadata?.serverContext).toBe('server says');
    expect(back.metadata?.userContext).toHaveLength(1);
    expect(back.metadata?.userContext?.[0]).toMatchObject({
      type: 'atomic-resource',
      subject: 'did:ad:x',
    });
  });

  it('stores a summary under the role summary and reads it back as a user message', () => {
    const entry = messageToEntry(
      { ...user('s', 'summary text'), metadata: { isSummary: true } },
      AGENT,
      1,
    );
    expect(entry.role).toBe('summary');
    expect(entryToMessage('s', entry)).toMatchObject({
      role: 'user',
      metadata: { isSummary: true },
    });
  });

  it('skips an entry it does not understand', () => {
    expect(entryToMessage('x', { a: AGENT, t: 'plain', c: 1 })).toBeUndefined();
  });
});

describe('writing', () => {
  it('appends in order and a re-save keeps the key and the time', async () => {
    const { store, chat, pages } = setup();
    const first = await addMessageToChatResource(
      user('u1', 'question'),
      chat as never,
      store,
    );
    const reply = await addMessageToChatResource(
      assistant('a1', 'par'),
      chat as never,
      store,
    );
    const second = await addMessageToChatResource(
      user('u2', 'follow-up'),
      chat as never,
      store,
    );
    // The reply completes after the follow-up was sent (a retry): same entry.
    const final = await addMessageToChatResource(
      assistant('a1', 'partial reply, now complete'),
      chat as never,
      store,
    );

    expect(final).toEqual(reply);
    expect(pages.size).toBe(1);
    const page = [...pages.values()][0];
    expect(page.saves).toBe(4);
    const entries = [...page.entries.values()].sort((a, b) => a.c - b.c);
    expect(entries.map(e => e.role)).toEqual(['user', 'assistant', 'user']);
    expect(entries[1].parts).toContain('now complete');
    expect(new Set(entries.map(e => e.c)).size).toBe(3);
    expect([first, reply, second].every(r => r.kind === 'entry')).toBe(true);
  });

  it('does not save a draft chat and sends the page when told to persist', async () => {
    const { store, chat, pages } = setup();
    await addMessageToChatResource(user('u1', 'q'), chat as never, store, {
      persistToServer: false,
    });
    await addMessageToChatResource(assistant('a1', 'r'), chat as never, store, {
      persistToServer: false,
    });
    const page = [...pages.values()][0];
    expect(page.saves).toBe(0);
    expect(page.entries.size).toBe(2);
  });

  it('starts a second page after 256 entries', async () => {
    const { store, chat, pages } = setup();

    for (let i = 0; i < 257; i++) {
      await addMessageToChatResource(
        user(`m${i}`, `t${i}`),
        chat as never,
        store,
      );
    }

    expect(pages.size).toBe(2);
    expect([...pages.values()].map(p => p.entries.size)).toEqual([256, 1]);
  });

  it('removes one entry, and the entries after a message', async () => {
    const { store, chat, pages } = setup();
    const messages = [user('u1', 'a'), assistant('a1', 'b'), user('u2', 'c')];
    const map = new Map<AtomicUIMessage, AiMessageRef>();

    for (const m of messages) {
      map.set(m, await addMessageToChatResource(m, chat as never, store));
    }

    const kept = await removeFollowingMessagesFromChatResource(
      messages[0],
      messages,
      map,
      chat as never,
      store,
    );
    expect(kept).toEqual([messages[0]]);
    const page = [...pages.values()][0];
    expect(page.entries.size).toBe(1);

    await removeMessageFromChatResource(
      map.get(messages[0])!,
      chat as never,
      store,
    );
    expect(page.entries.size).toBe(0);
  });
});

describe('reading', () => {
  it('lists entries oldest first by c, whatever their keys', async () => {
    const { store, chat, pages } = setup();
    // Migrated keys carry the old creation time, c was raised to keep the list's order.
    const page = new FakePage('did:ad:pageM');
    pages.set(page.subject, page);
    page.entries.set('2-aaaaaaaa', {
      ...messageToEntry(user('x', 'second'), AGENT, 20),
    });
    page.entries.set('3-bbbbbbbb', {
      ...messageToEntry(user('y', 'first'), AGENT, 10),
    });
    const { rememberPage, scopeKey } = await import('@helpers/chatLog');
    rememberPage(
      store,
      scopeKey('https://atomicdata.dev/properties/parent', chat.subject),
      page.subject,
    );

    const loaded = [...(await loadChatMessages(chat as never, store)).keys()];
    expect(loaded.map(m => (m.parts[0] as { text: string }).text)).toEqual([
      'first',
      'second',
    ]);
  });

  it('hides an old ai-message whose entry exists and keeps the others in front', async () => {
    const { store, chat, pages } = setup('did:ad:chat2');
    const migratedOld = 'did:ad:oldmsg1';
    const key = migratedEntryKey(5, migratedOld);
    const page = new FakePage('did:ad:pageN');
    pages.set(page.subject, page);
    page.entries.set(key, messageToEntry(user('m', 'migrated'), AGENT, 6));
    page.entries.set(
      'ff-00000000',
      messageToEntry(user('n', 'new'), AGENT, 100),
    );
    const { rememberPage, scopeKey } = await import('@helpers/chatLog');
    rememberPage(
      store,
      scopeKey('https://atomicdata.dev/properties/parent', chat.subject),
      page.subject,
    );
    (chat as unknown as { props: Record<string, unknown> }).props.messages = [
      migratedOld,
    ];

    const loaded = await loadChatMessages(chat as never, store);
    expect(
      [...loaded.keys()].map(m => (m.parts[0] as { text: string }).text),
    ).toEqual(['migrated', 'new']);
  });

  it('merges two ordered lists by time, the first going first on a tie', () => {
    const a = [
      { at: 1, n: 'a1' },
      { at: 5, n: 'a2' },
    ];
    const b = [
      { at: 1, n: 'b1' },
      { at: 3, n: 'b2' },
      { at: 9, n: 'b3' },
    ];
    expect(mergeByTime(a, b).map(x => x.n)).toEqual([
      'a1',
      'b1',
      'b2',
      'a2',
      'b3',
    ]);
  });
});
