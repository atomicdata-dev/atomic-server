import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as Sentry from '@sentry/react';
import { initSentry } from './sentry';
vi.mock('@sentry/react', () => ({ init: vi.fn() }));
describe('Sentry configuration', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal('__APP_VERSION__', 'test');
    vi.stubGlobal('__GIT_COMMIT__', 'abc123');
    vi.stubEnv('VITE_SENTRY_DSN', 'https://public@example.com/123');
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });
  it('initializes packaged WebViews without injected server configuration', () => {
    vi.stubGlobal('window', {});
    vi.stubEnv('VITE_SENTRY_ENVIRONMENT', 'staging');
    initSentry();
    expect(Sentry.init).toHaveBeenCalledWith(
      expect.objectContaining({
        dsn: 'https://public@example.com/123',
        environment: 'staging',
        release: 'atomic-data-browser@test+abc123',
      }),
    );
  });
  it('allows a runtime empty DSN to disable a configured build', () => {
    vi.stubGlobal('window', { __ATOMIC_SENTRY__: { dsn: '' } });
    initSentry();
    expect(Sentry.init).not.toHaveBeenCalled();
  });
  it('attributes reports to the runtime environment and exact build', () => {
    vi.stubGlobal('window', {
      __ATOMIC_SENTRY__: {
        dsn: 'https://runtime@example.com/456',
        environment: 'staging',
      },
    });
    initSentry();
    expect(Sentry.init).toHaveBeenCalledWith(
      expect.objectContaining({
        dsn: 'https://runtime@example.com/456',
        environment: 'staging',
        release: 'atomic-data-browser@test+abc123',
        sendDefaultPii: false,
        tracesSampleRate: 0,
      }),
    );
  });
});
