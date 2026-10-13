import React from 'react';
import Bugsnag from '@bugsnag/js';
import BugsnagPluginReact, {
  BugsnagErrorBoundary,
} from '@bugsnag/plugin-react';

import * as Sentry from '@sentry/react';

import { isDev } from '../config';

export function handleErrorBugsnag(e: Error): void {
  // Only when `initBugsnag` ran (an API key is configured). Calling `notify`
  // before `start` logs "Bugsnag.notify() was called before Bugsnag.start()"
  // for every error, on installs that never use Bugsnag.
  if (!isDev() && Bugsnag.isStarted()) {
    Bugsnag.notify(e);
  }
}

/** No-op unless Sentry was initialised (a DSN is configured and not in dev). */
export function reportStoreError(e: Error): void {
  Sentry.captureException(e, { tags: { source: 'store' } });
}

export function initBugsnag(apiKey: string): BugsnagErrorBoundary {
  Bugsnag.start({
    apiKey,
    plugins: [new BugsnagPluginReact()],
    releaseStage: isDev() ? 'development' : 'production',
    enabledReleaseStages: ['production'],
    autoDetectErrors: !isDev(),
  });

  const plugin = Bugsnag.getPlugin('react')!;

  return plugin.createErrorBoundary(
    React as unknown as Parameters<typeof plugin.createErrorBoundary>[0],
  );
}
