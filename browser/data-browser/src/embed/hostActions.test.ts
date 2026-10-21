import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  openNative,
  reportShown,
  reportTheme,
  setActionsHost,
  SHOWN_DELAY_MS,
} from './hostActions';

afterEach(() => setActionsHost(undefined));

it('is false without an app', async () => {
  expect(await openNative('chatroom', 'did:ad:room')).toBe(false);
});

it('asks the app and reports its answer', async () => {
  const call = vi.fn().mockResolvedValue(true);

  setActionsHost({ call });
  expect(await openNative('chatroom', 'did:ad:room', 'Standup')).toBe(true);
  expect(call).toHaveBeenCalledWith('openNative', [
    'chatroom',
    'did:ad:room',
    'Standup',
  ]);
});

it('is false when the app declines or does not know the call', async () => {
  setActionsHost({ call: vi.fn().mockResolvedValue(false) });
  expect(await openNative('chatroom', 'did:ad:room')).toBe(false);

  setActionsHost({ call: vi.fn().mockRejectedValue(new Error('unknown')) });
  expect(await openNative('chatroom', 'did:ad:room')).toBe(false);
});

describe('reportShown', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('reports a resource the page stays on, once', () => {
    const call = vi.fn().mockResolvedValue(null);

    setActionsHost({ call });
    reportShown('did:ad:folder');
    vi.advanceTimersByTime(SHOWN_DELAY_MS - 1);
    expect(call).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(call).toHaveBeenCalledWith('opened', ['did:ad:folder']);

    reportShown('did:ad:folder');
    vi.advanceTimersByTime(SHOWN_DELAY_MS);
    expect(call).toHaveBeenCalledTimes(1);
  });

  it('skips a resource passed through, and a page without one', () => {
    const call = vi.fn().mockResolvedValue(null);

    setActionsHost({ call });
    reportShown('did:ad:a');
    vi.advanceTimersByTime(SHOWN_DELAY_MS / 2);
    reportShown('did:ad:b');
    vi.advanceTimersByTime(SHOWN_DELAY_MS);
    expect(call.mock.calls).toEqual([['opened', ['did:ad:b']]]);

    reportShown('did:ad:c');
    reportShown(undefined);
    vi.advanceTimersByTime(SHOWN_DELAY_MS);
    expect(call).toHaveBeenCalledTimes(1);
  });

  it('does nothing without an app, or when the app does not know the call', async () => {
    reportShown('did:ad:a');
    vi.advanceTimersByTime(SHOWN_DELAY_MS);

    setActionsHost({ call: vi.fn().mockRejectedValue(new Error('unknown')) });
    reportShown('did:ad:a');
    vi.advanceTimersByTime(SHOWN_DELAY_MS);
    await vi.runAllTimersAsync();
  });
});

it('tells the app the theme chosen on the page', () => {
  const call = vi.fn().mockResolvedValue(true);

  reportTheme('dark');
  setActionsHost({ call });
  reportTheme('light');
  reportTheme('auto');
  expect(call.mock.calls).toEqual([
    ['theme', ['light']],
    ['theme', ['auto']],
  ]);
});
