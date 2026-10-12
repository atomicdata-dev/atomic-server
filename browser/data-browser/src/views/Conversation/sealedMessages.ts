import { createContext, useContext } from 'react';
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
