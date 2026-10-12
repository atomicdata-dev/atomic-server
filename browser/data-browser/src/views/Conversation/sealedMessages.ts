import { createContext, useContext } from 'react';
import { migratedKeyHash } from '@tomic/react';
import { parseEntryId } from '../../helpers/chatLog';
import type { SealedPayload } from '../../helpers/conversations/conversationCrypto';

/**
 * Decrypted SealedMessages, by subject. A conversation opens its messages once
 * and provides them here, so the chat's Message rows show the text instead of
 * reading `description`. `null`: a message this reader can't open. Absent: not
 * opened yet, or not a sealed message.
 */
export const SealedMessagesContext = createContext<Map<
  string,
  SealedPayload | null
> | null>(null);

export type SealedState =
  | { sealed: false }
  | { sealed: true; payload: SealedPayload | null | undefined };

/** Whether `subject` is a sealed message, and its content once opened. */
export function useSealedMessage(subject: string): SealedState {
  const opened = useContext(SealedMessagesContext);

  if (!opened) {
    return { sealed: false };
  }

  return { sealed: true, payload: opened.get(subject) };
}

/**
 * A reply inside a payload names the message it answers by its id when it was
 * sent. For a message that was moved into the log afterwards that is the old
 * `SealedMessage` subject, which no longer exists; the entry it became has the
 * same hash in its key (`migratedEntryKey`). Point such replies at the entry,
 * when it is listed. The payload itself is encrypted and stays as it was.
 */
export function resolveReplies(
  payloads: Map<string, SealedPayload | null>,
  messages: string[],
): Map<string, SealedPayload | null> {
  const byHash = new Map<string, string>();

  for (const id of messages) {
    const key = parseEntryId(id)?.key;

    if (key) byHash.set(key.slice(key.indexOf('-') + 1), id);
  }

  if (byHash.size === 0) return payloads;

  const resolved = new Map<string, SealedPayload | null>();

  for (const [id, payload] of payloads) {
    const replyTo = payload?.replyTo;
    const target =
      replyTo && !parseEntryId(replyTo)
        ? byHash.get(migratedKeyHash(replyTo))
        : undefined;

    resolved.set(
      id,
      payload && target ? { ...payload, replyTo: target } : payload,
    );
  }

  return resolved;
}
