import React from 'react';
import Bugsnag from '@bugsnag/js';
import BugsnagPluginReact, {
  BugsnagErrorBoundary,
} from '@bugsnag/plugin-react';

import { isDev } from '../config';

export function handleErrorBugsnag(e: Error): void {
  if (!isDev) {
    Bugsnag.notify(e);
  }
}

export function initBugsnag(apiKey: string): BugsnagErrorBoundary {
  Bugsnag.start({
    apiKey,
    plugins: [new BugsnagPluginReact()],
    releaseStage: isDev() ? 'development' : 'production',
    enabledReleaseStages: ['production'],
    autoDetectErrors: !isDev(),
  });

  return Bugsnag.getPlugin('react')!.createErrorBoundary(React);
}
