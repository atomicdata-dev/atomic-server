// @wc-ignore-file
import * as Sentry from '@sentry/react';

export const FEEDBACK_MESSAGE_MAX_LENGTH = 4096;
/** AI chat reports carry a transcript, so they get the larger Sentry cap. */
export const AI_CHAT_FEEDBACK_MAX_LENGTH = 60_000;
const AI_CHAT_HEAD_LENGTH = 4000;
const AI_CHAT_OMISSION = '\n[Middle of the report omitted to fit]\n';

/** Keep the person's description (head) and the most recent turns (tail). */
function capAIChatMessage(message: string): string {
  if (message.length <= AI_CHAT_FEEDBACK_MAX_LENGTH) return message;

  const tail =
    AI_CHAT_FEEDBACK_MAX_LENGTH - AI_CHAT_HEAD_LENGTH - AI_CHAT_OMISSION.length;

  return `${message.slice(0, AI_CHAT_HEAD_LENGTH)}${AI_CHAT_OMISSION}${message.slice(-tail)}`;
}

export async function submitFeedback(
  message: string,
  email: string,
  source = 'sidebar',
  diagnostics?: string,
): Promise<string> {
  if (!message.trim()) throw new Error('Feedback is empty');

  const text =
    source === 'ai-chat' ? capAIChatMessage(message.trim()) : message.trim();

  if (source !== 'ai-chat' && text.length > FEEDBACK_MESSAGE_MAX_LENGTH) {
    throw new Error('Feedback must be at most 4096 characters');
  }

  if (!Sentry.isEnabled()) throw new Error('Feedback reporting is unavailable');

  return Sentry.sendFeedback(
    {
      message: text,
      email: email.trim() || undefined,
      url: '',
      source,
    },
    {
      includeReplay: false,
      ...(diagnostics
        ? {
            attachments: [
              {
                filename: 'diagnostics.json',
                contentType: 'application/json',
                data: diagnostics,
              },
            ],
          }
        : {}),
    },
  );
}

/** Prefill a report without attaching a stack trace or the current resource URL. */
export function errorFeedbackMessage(error: Error): string {
  return `I encountered this error:\n${error.name}: ${error.message}`.slice(
    0,
    10_000,
  );
}
