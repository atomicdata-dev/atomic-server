// @wc-ignore-file
import type { Event } from '@sentry/react';

/** Where a report was sent from. Anything else is reported as the sidebar. */
const FEEDBACK_SOURCES = new Set(['sidebar', 'error', 'ai-chat']);

/** Feedback must not inherit scope breadcrumbs, private URLs, or identifying user context. */
export function sanitizeFeedbackEvent(event: Event): Event {
  if (event.type !== 'feedback') return event;
  const feedback = event.contexts?.feedback;

  // Sentry derives browser/OS details from this header after ingestion.
  // Do not retain the request URL, Referer, cookies, or other headers.
  const userAgent = Object.entries(event.request?.headers ?? {}).find(
    ([name]) => name.toLowerCase() === 'user-agent',
  )?.[1];

  return {
    platform: event.platform,
    level: event.level,
    ...(typeof userAgent === 'string'
      ? { request: { headers: { 'User-Agent': userAgent } } }
      : {}),
    type: 'feedback',
    // Only the hashed agent pseudonym (`identifyAgentInSentry`); never the
    // email, IP address or username.
    ...(typeof event.user?.id === 'string' && event.user.id
      ? { user: { id: event.user.id } }
      : {}),
    event_id: event.event_id,
    timestamp: event.timestamp,
    release: event.release,
    environment: event.environment,
    contexts: {
      ...(event.contexts?.browser
        ? { browser: nameAndVersion(event.contexts.browser) }
        : {}),
      ...(event.contexts?.os ? { os: nameAndVersion(event.contexts.os) } : {}),
      feedback: {
        message: typeof feedback?.message === 'string' ? feedback.message : '',
        contact_email:
          typeof feedback?.contact_email === 'string'
            ? feedback.contact_email
            : undefined,
        source:
          typeof feedback?.source === 'string' &&
          FEEDBACK_SOURCES.has(feedback.source)
            ? feedback.source
            : 'sidebar',
        url: '',
      },
    },
  };
}

function nameAndVersion(context: { name?: unknown; version?: unknown }) {
  return {
    ...(typeof context.name === 'string' ? { name: context.name } : {}),
    ...(typeof context.version === 'string'
      ? { version: context.version }
      : {}),
  };
}
