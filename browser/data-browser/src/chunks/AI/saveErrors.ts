// @wc-ignore-file
import { isNotEnrolledMessage } from '@tomic/react';
import { reportStoreError } from '@helpers/loggingHandlers';

/** Toast id shared by every "could not save this chat message" notification. */
export const CHAT_SAVE_TOAST_ID = 'ai-chat-save';

const errorMessage = (error: unknown): string | undefined => {
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;

  return undefined;
};

/**
 * Handles a failed attempt to persist an AI chat message.
 *
 * When the connected node refuses the chat's drive ("not enrolled for sync on
 * this node") the write is not lost: the outbox parks it and the data stays on
 * this device. `Store.notifyBlockedSync` already tells the person once per
 * drive, so a second "failed" toast here would be misleading. Every other
 * failure is reported and `notify` is called so the caller can show its toast.
 */
export function handleChatSaveError(
  error: unknown,
  notify: (opts: { id: string }) => void,
): void {
  console.error(error);

  if (isNotEnrolledMessage(errorMessage(error))) return;

  reportStoreError(error instanceof Error ? error : new Error(String(error)));
  notify({ id: CHAT_SAVE_TOAST_ID });
}
