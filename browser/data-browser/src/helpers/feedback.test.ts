import { describe, expect, it, vi } from 'vitest';
import * as Sentry from '@sentry/react';
import { submitFeedback } from './feedback';
vi.mock('@sentry/react', () => ({ isEnabled: vi.fn(), sendFeedback: vi.fn() }));
describe('feedback delivery', () => {
  it('rejects disabled reporting', async () => {
    vi.mocked(Sentry.isEnabled).mockReturnValue(false);
    await expect(submitFeedback('Problem', '')).rejects.toThrow();
    expect(Sentry.sendFeedback).not.toHaveBeenCalled();
  });
  it('preserves failed delivery for retry', async () => {
    vi.mocked(Sentry.isEnabled).mockReturnValue(true);
    vi.mocked(Sentry.sendFeedback).mockRejectedValue(new Error('offline'));
    await expect(submitFeedback('Problem', '')).rejects.toThrow('offline');
  });
  it('sends supplied text without replay or a private resource URL', async () => {
    vi.mocked(Sentry.isEnabled).mockReturnValue(true);
    vi.mocked(Sentry.sendFeedback).mockResolvedValue('receipt');
    await expect(
      submitFeedback(' Problem ', ' person@example.com '),
    ).resolves.toBe('receipt');
    expect(Sentry.sendFeedback).toHaveBeenLastCalledWith(
      {
        message: 'Problem',
        email: 'person@example.com',
        url: '',
        source: 'sidebar',
      },
      { includeReplay: false },
    );
  });
  it('rejects blank feedback', async () => {
    await expect(submitFeedback(' ', '')).rejects.toThrow();
  });
});
