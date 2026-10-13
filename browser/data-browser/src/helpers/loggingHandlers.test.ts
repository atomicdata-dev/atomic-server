import { beforeEach, describe, expect, it, vi } from 'vitest';
import Bugsnag from '@bugsnag/js';
import { handleErrorBugsnag } from './loggingHandlers';

vi.mock('@bugsnag/js', () => ({
  default: { isStarted: vi.fn(), notify: vi.fn(), start: vi.fn() },
}));
vi.mock('@bugsnag/plugin-react', () => ({ default: class {} }));
vi.mock('@sentry/react', () => ({ captureException: vi.fn() }));
vi.mock('../config', () => ({ isDev: () => false }));

describe('handleErrorBugsnag', () => {
  beforeEach(() => vi.clearAllMocks());

  it('stays quiet when Bugsnag was never started', () => {
    vi.mocked(Bugsnag.isStarted).mockReturnValue(false);
    handleErrorBugsnag(new Error('boom'));
    expect(Bugsnag.notify).not.toHaveBeenCalled();
  });

  it('notifies once Bugsnag runs', () => {
    vi.mocked(Bugsnag.isStarted).mockReturnValue(true);
    const error = new Error('boom');
    handleErrorBugsnag(error);
    expect(Bugsnag.notify).toHaveBeenCalledWith(error);
  });
});
