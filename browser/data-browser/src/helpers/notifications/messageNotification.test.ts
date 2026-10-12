import { describe, it, expect } from 'vitest';
import { dataBrowser } from '@tomic/react';
import {
  classifyMessage,
  entryFacts,
  isCandidate,
  type MessageContext,
  type MessageFacts,
} from './messageNotification';

const ME = 'did:ad:agent:me';
const THEM = 'did:ad:agent:them';
const ROOM = 'https://example.com/room';
const DOC = 'https://example.com/doc';
const MY_MSG = 'https://example.com/my-msg';
const START = 1_000_000;

const ctx: MessageContext = {
  me: ME,
  since: START,
  classesOf: s => (s === ROOM ? [dataBrowser.classes.chatroom] : []),
  creatorOf: s => (s === MY_MSG ? ME : s === DOC ? ME : THEM),
};

const msg = (extra: Partial<MessageFacts>): MessageFacts => ({
  subject: 'https://example.com/msg',
  isA: [dataBrowser.classes.message],
  createdBy: THEM,
  createdAt: START + 10,
  ...extra,
});

describe('message notifications', () => {
  it('announces a new message in a chat room', () => {
    expect(classifyMessage(msg({ parent: ROOM }), ctx)).toMatchObject({
      kind: 'chat',
      target: ROOM,
      openComments: false,
    });
  });

  it('skips my own messages and the backlog', () => {
    expect(isCandidate(msg({ createdBy: ME }), ctx)).toBe(false);
    expect(isCandidate(msg({ createdAt: START - 1 }), ctx)).toBe(false);
  });

  it('waits when the author or time is not known yet', () => {
    expect(isCandidate(msg({ createdAt: undefined }), ctx)).toBeUndefined();
  });

  it('skips meeting trail events', () => {
    const event = msg({
      parent: ROOM,
      isA: [dataBrowser.classes.message, dataBrowser.classes.followEvent],
    });
    expect(classifyMessage(event, ctx)).toBeUndefined();
  });

  it('announces a comment on something I made, opening its comments', () => {
    expect(classifyMessage(msg({ about: DOC }), ctx)).toMatchObject({
      kind: 'comment',
      target: DOC,
      openComments: true,
    });
  });

  it('ignores comments on things other people made', () => {
    const other = 'https://example.com/theirs';
    expect(classifyMessage(msg({ about: other }), ctx)).toBeUndefined();
  });

  it('calls a reply to my message a reply, wherever it is', () => {
    const other = 'https://example.com/theirs';
    expect(
      classifyMessage(msg({ about: other, replyTo: MY_MSG }), ctx),
    ).toMatchObject({ kind: 'reply', target: other, openComments: true });
    expect(
      classifyMessage(msg({ parent: ROOM, replyTo: MY_MSG }), ctx),
    ).toMatchObject({ kind: 'reply', target: ROOM });
  });

  it('ignores messages under something that is not a chat room', () => {
    const folder = 'https://example.com/folder';
    expect(classifyMessage(msg({ parent: folder }), ctx)).toBeUndefined();
  });
});

describe('notifications for chat log entries', () => {
  const PAGE = 'did:ad:page';
  const entry = (extra = {}) => ({ a: THEM, c: START + 10, ...extra });
  const facts = (
    page: { parent?: string; about?: string },
    e = entry(),
    key = '19e-0000000a',
  ) => entryFacts(PAGE, page, key, e);

  it('addresses the entry as page#key and takes author and time from it', () => {
    expect(facts({ parent: ROOM })).toMatchObject({
      subject: `${PAGE}#19e-0000000a`,
      createdBy: THEM,
      createdAt: START + 10,
      parent: ROOM,
      isA: [dataBrowser.classes.message],
    });
  });

  it('announces a new entry in a chat room', () => {
    expect(classifyMessage(facts({ parent: ROOM }), ctx)).toMatchObject({
      kind: 'chat',
      target: ROOM,
      openComments: false,
    });
  });

  it('announces an entry in the comments on something I made', () => {
    expect(classifyMessage(facts({ about: DOC }), ctx)).toMatchObject({
      kind: 'comment',
      target: DOC,
      openComments: true,
    });
  });

  it('skips my own entries and the backlog', () => {
    expect(isCandidate(facts({ parent: ROOM }, entry({ a: ME })), ctx)).toBe(
      false,
    );
    expect(
      isCandidate(facts({ parent: ROOM }, entry({ c: START - 1 })), ctx),
    ).toBe(false);
  });

  it('announces a reply to my entry, found by its entry id', () => {
    const mine = `${PAGE}#19e-00000001`;
    const withMine: MessageContext = {
      ...ctx,
      creatorOf: s => (s === mine ? ME : THEM),
    };
    expect(
      classifyMessage(facts({ parent: ROOM }, entry({ r: mine })), withMine),
    ).toMatchObject({ kind: 'reply' });
  });

  it('does not announce an entry in something that is not a chat', () => {
    expect(
      classifyMessage(facts({ parent: 'https://example.com/folder' }), ctx),
    ).toBeUndefined();
  });
});
