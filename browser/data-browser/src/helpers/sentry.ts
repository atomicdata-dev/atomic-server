import * as Sentry from '@sentry/react';
import { StoreEvents, type Store } from '@tomic/react';

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
  /**
   * Same-origin path the host relays envelopes from to Sentry. Browsers with
   * tracking protection or an ad blocker refuse requests to sentry.io, which
   * made every report and feedback submission fail for those users.
   */
  tunnel?: string;
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

  // A dev server reports nothing. Vite's hot reload legitimately throws while
  // swapping modules ("Cannot access X before initialization", "_s is not a
  // function", all with `@react-refresh` frames), which is not a defect in
  // anything shipped. Those arrived in Sentry rated above every real bug.
  // Set VITE_SENTRY_ENVIRONMENT to report from a local build on purpose.
  if (environment === 'development') return;

  Sentry.init({
    dsn,
    environment,
    tunnel: runtime?.tunnel || undefined,
    release: `atomic-data-browser@${__APP_VERSION__}+${__GIT_COMMIT__}`,
    sendDefaultPii: false,
    // No performance tracing or session replay. Explicit feedback is sent
    // only when the user submits the sidebar form.
    tracesSampleRate: 0,
    // One release-health session per page load. The default ('route') starts
    // a new session on every in-app navigation, which sent two requests to the
    // tunnel each time.
    integrations: [Sentry.browserSessionIntegration({ lifecycle: 'page' })],
  });

  // Runs before the Dedupe integration and before any `beforeSend`, so it sees
  // every event the page raised, including those the SDK is about to drop.
  Sentry.getClient()?.on(
    'preprocessEvent',
    countRepeatedEvents(reportRepeatedEvent),
  );
}

/** How many times an event repeats on one page load before we say so. */
const REPEAT_REPORT_AT = [10, 100, 1000, 10_000, 100_000];
/** Distinct errors tracked per page load. A bound, not a target. */
const MAX_TRACKED_EVENTS = 200;
/** Marks the summary event so it never counts itself. */
const REPEAT_SUMMARY_TAG = 'repeatSummary';

function eventKey(event: Sentry.Event): string | undefined {
  const exception = event.exception?.values?.[0];
  const text = exception
    ? `${exception.type ?? 'Error'}: ${exception.value ?? ''}`
    : event.message;

  return text ? withoutIdentifiers(text).slice(0, 200) : undefined;
}

/**
 * Count how often the same error is raised on this page load.
 *
 * The SDK drops an event equal to the one before it (Dedupe), and the server
 * drops what exceeds a rate limit. A loop that raised the same error ten
 * thousand times therefore showed up in Sentry as a single event, and we could
 * not tell a hiccup from a runaway. `report` is called once per power of ten.
 */
export function countRepeatedEvents(
  report: (key: string, count: number) => void,
): (event: Sentry.Event) => void {
  const counts = new Map<string, number>();

  return event => {
    if (event.tags?.[REPEAT_SUMMARY_TAG]) return;

    const key = eventKey(event);

    if (!key) return;

    const count = (counts.get(key) ?? 0) + 1;

    // Past the bound, keep counting what is tracked but track nothing new.
    if (count === 1 && counts.size >= MAX_TRACKED_EVENTS) return;

    counts.set(key, count);

    if (REPEAT_REPORT_AT.includes(count)) report(key, count);
  };
}

function reportRepeatedEvent(key: string, count: number): void {
  Sentry.captureMessage(`Event repeated ${count} times`, {
    level: 'warning',
    // Count left out of the fingerprint: one issue per error, not per tier.
    fingerprint: ['repeated-event', key],
    tags: { [REPEAT_SUMMARY_TAG]: 'true' },
    extra: { error: key, count },
  });
}

/**
 * A stable, anonymous id for the signed-in agent, so Sentry can count how many
 * people an error touches and show everything one person hit. The agent id is
 * hashed: it is a public key, and what we store cannot be traced back to it,
 * let alone to an email address (`sendDefaultPii` stays off).
 */
export async function agentPseudonym(
  subject: string,
): Promise<string | undefined> {
  if (!globalThis.crypto?.subtle) return undefined;

  const digest = await globalThis.crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(subject),
  );

  return Array.from(new Uint8Array(digest).slice(0, 8), byte =>
    byte.toString(16).padStart(2, '0'),
  ).join('');
}

/** Keep Sentry's user in step with the store's agent. */
export function identifyAgentInSentry(store: Store): () => void {
  let latest = 0;

  async function identify(subject: string | undefined) {
    const turn = ++latest;
    const id = subject ? await agentPseudonym(subject) : undefined;

    // A newer sign-in or sign-out overtook the hash.
    if (turn !== latest) return;

    Sentry.setUser(id ? { id } : null);
  }

  void identify(store.getAgent()?.subject);

  return store.on(StoreEvents.AgentChanged, agent => {
    void identify(agent?.subject);
  });
}

/** Identifiers differ per resource; the failure itself is what groups. */
function withoutIdentifiers(message: string): string {
  return message.replace(/(?:atomic|did:ad):[\w-]+/g, '<id>');
}

/**
 * Report a write that keeps failing while the outbox retries it. Those
 * failures only ever reached the console, so a drive that could not sync (for
 * instance a server that never received its root) was invisible to us.
 */
export function reportRepeatedCommitFailures(store: Store): () => void {
  return store.on(StoreEvents.CommitRepeatedlyFailing, failure => {
    if (!Sentry.isEnabled()) return;

    const message = withoutIdentifiers(failure.error.message);

    // Extras are scrubbed server-side ("[Filtered]"), so the cause goes in the
    // title and in a tag, which are not.
    Sentry.captureMessage(`Commit keeps failing: ${message.slice(0, 160)}`, {
      level: 'warning',
      fingerprint: ['commit-keeps-failing', failure.server, message],
      tags: {
        server: failure.server,
        error_kind: message.slice(0, 200),
        connected: String(failure.connected),
        genesis: String(failure.isGenesis),
      },
      extra: {
        subject: failure.subject,
        drive: failure.drive,
        failures: failure.failures,
        ageSeconds: Math.round(failure.ageMs / 1000),
        outboxSize: failure.outboxSize,
        rearmedAfterResync: failure.rearmedAfterResync,
        error: failure.error.message,
      },
    });
  });
}

/**
 * Report a failure the person only saw as a toast or inline text. Those never
 * reach the console or Sentry on their own, so a setup that failed for someone
 * left nothing to look at afterwards. Grouped by `what`, a fixed phrase.
 */
export function reportUserFacingFailure(
  what: string,
  context: Record<string, unknown> = {},
): void {
  if (!Sentry.isEnabled()) return;

  Sentry.captureMessage(what, {
    level: 'warning',
    fingerprint: ['user-facing-failure', what],
    extra: context,
  });
}

/** Whether problems are reported at all: false unless this install opted in. */
export function isErrorReportingEnabled(): boolean {
  return Sentry.isEnabled();
}

const reportedSyncProblems = new Set<string>();

/**
 * Report a sync problem the Sync page found that nothing else reports, once
 * per problem. A commit that keeps failing is reported by
 * {@link reportRepeatedCommitFailures}; pass only what that does not cover, or
 * it is counted twice.
 */
export function reportSyncProblem(problem: {
  key: string;
  server: string;
  detail?: string;
}): void {
  if (!Sentry.isEnabled()) return;

  const message = withoutIdentifiers(problem.detail ?? '');
  const id = [problem.key, problem.server, message].join('|');

  if (reportedSyncProblems.has(id)) return;

  reportedSyncProblems.add(id);

  Sentry.captureMessage(/* @wc-ignore */ 'Sync problem', {
    level: 'warning',
    fingerprint: ['sync-problem', problem.key, problem.server, message],
    tags: { server: problem.server },
    extra: { detail: problem.detail },
  });
}
