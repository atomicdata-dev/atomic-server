// @wc-ignore-file
// Which new messages are worth telling someone about.
//
// Chat messages and comments are the same class: a Message with a `parent`
// (the chat room) or an `about` (the resource it comments on), and optionally
// a `replyTo`. So one rule set covers both. Kept free of the store and React
// so the rules can be tested as plain data.
import { dataBrowser } from '@tomic/react';

export type MessageNotificationKind = 'reply' | 'comment' | 'chat';

export interface MessageFacts {
  subject: string;
  isA: string[];
  createdBy?: string;
  createdAt?: number;
  parent?: string;
  about?: string;
  replyTo?: string;
}

/**
 * Facts about one entry of a ChatLog page, as if it were a Message resource:
 * its id is `<page>#<key>`, the author and time are the entry's own, and the
 * chat (`parent`) or the commented item (`about`) are the page's.
 */
export function entryFacts(
  pageSubject: string,
  page: Pick<MessageFacts, 'parent' | 'about'>,
  key: string,
  entry: { a: string; c: number; r?: string; k?: unknown },
): MessageFacts {
  return {
    subject: `${pageSubject}#${key}`,
    isA: [
      dataBrowser.classes.message,
      ...(entry.k === dataBrowser.classes.followEvent
        ? [dataBrowser.classes.followEvent]
        : []),
    ],
    createdBy: entry.a,
    createdAt: entry.c,
    parent: page.parent,
    about: page.about,
    replyTo: entry.r,
  };
}

export interface MessageContext {
  /** The signed-in agent. Without one there is nobody to notify. */
  me?: string;
  /** Messages older than this (ms) are backlog, not news. */
  since: number;
  /** Classes of a resource, if it could be loaded. */
  classesOf: (subject: string) => string[] | undefined;
  /** Creator of a resource, if it could be loaded. */
  creatorOf: (subject: string) => string | undefined;
}

export interface MessageNotification {
  kind: MessageNotificationKind;
  message: string;
  author: string;
  /** What to open when the notification is clicked. */
  target: string;
  /** Open the comments panel on `target` too. */
  openComments: boolean;
}

/**
 * Whether a message is too old, too own or not a message at all, before
 * anything about its surroundings is loaded. `undefined` means: can't tell
 * yet (its creation time or author hasn't arrived), ask again later.
 */
export function isCandidate(
  msg: MessageFacts,
  ctx: Pick<MessageContext, 'me' | 'since'>,
): boolean | undefined {
  if (!msg.isA.includes(dataBrowser.classes.message)) return false;
  // System trail in meetings ("Viewing …", "Started").
  if (msg.isA.includes(dataBrowser.classes.followEvent)) return false;
  if (!ctx.me) return false;
  if (msg.createdAt === undefined || !msg.createdBy) return undefined;
  if (msg.createdAt < ctx.since) return false;

  return msg.createdBy !== ctx.me;
}

/** Decides what, if anything, a candidate message should notify about. */
export function classifyMessage(
  msg: MessageFacts,
  ctx: MessageContext,
): MessageNotification | undefined {
  if (!isCandidate(msg, ctx) || !msg.createdBy) return undefined;

  const author = msg.createdBy;
  const isComment = !!msg.about;
  const target = msg.about ?? msg.parent;

  if (!target) return undefined;

  const base = {
    message: msg.subject,
    author,
    target,
    openComments: isComment,
  };

  if (msg.replyTo && ctx.creatorOf(msg.replyTo) === ctx.me) {
    return { ...base, kind: 'reply' };
  }

  if (isComment && ctx.creatorOf(msg.about!) === ctx.me) {
    return { ...base, kind: 'comment' };
  }

  if (
    !isComment &&
    msg.parent &&
    ctx.classesOf(msg.parent)?.includes(dataBrowser.classes.chatroom)
  ) {
    return { ...base, kind: 'chat' };
  }

  return undefined;
}
