import * as Sentry from '@sentry/react';

/**
 * Browser error reporting. Strictly opt-in: nothing is initialised, and no
 * network request is ever made, unless a DSN is provided.
 *
 * The DSN comes from one of two places:
 * - Runtime: atomic-server injects `window.__ATOMIC_SENTRY__` into the served
 *   index.html when started with `--sentry-dsn-browser` / `SENTRY_DSN_BROWSER`.
 *   This keeps the shipped bundle identical for every install; only servers
 *   that opt in get a reporting front-end.
 * - Build time: `VITE_SENTRY_DSN`, for builds that aren't served by
 *   atomic-server (the Tauri desktop app, a hosted static build).
 */
interface RuntimeSentryConfig {
  dsn?: string;
  environment?: string;
}

declare global {
  interface Window {
    __ATOMIC_SENTRY__?: RuntimeSentryConfig;
  }
}

export function initSentry(): void {
  if (typeof window === 'undefined') return;

  const runtime = window.__ATOMIC_SENTRY__;
  const dsn =
    runtime?.dsn ?? (import.meta.env.VITE_SENTRY_DSN as string | undefined);

  if (!dsn) return;

  const environment =
    runtime?.environment ||
    (import.meta.env.VITE_SENTRY_ENVIRONMENT as string | undefined) ||
    (import.meta.env.DEV ? 'development' : 'production');

  Sentry.init({
    dsn,
    environment,
    release: `atomic-data-browser@${__APP_VERSION__}+${__GIT_COMMIT__}`,
    sendDefaultPii: false,
    // No performance tracing or session replay. Explicit feedback is sent
    // only when the user submits the sidebar form.
    tracesSampleRate: 0,
  });
}
