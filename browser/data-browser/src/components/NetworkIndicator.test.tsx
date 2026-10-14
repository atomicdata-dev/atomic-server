// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, act, cleanup } from '@testing-library/react';
import { NetworkIndicator } from './NetworkIndicator';

const mocks = vi.hoisted(() => ({
  connected: undefined as ((connected: boolean) => void) | undefined,
  toast: Object.assign(vi.fn(), { dismiss: vi.fn() }),
  unsubscribe: vi.fn(),
}));
vi.mock('react-hot-toast', () => ({ default: mocks.toast }));
vi.mock('../hooks/useOnline', () => ({ useOnline: () => true }));
const store = {
  on: (_event: unknown, callback: (connected: boolean) => void) => {
    mocks.connected = callback;

    return mocks.unsubscribe;
  },
};
vi.mock('@tomic/react', () => ({
  StoreEvents: { ConnectionChanged: 'connected' },
  useStore: () => store,
}));

describe('NetworkIndicator reconnects', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
    localStorage.clear();
  });
  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  it('does not cover editing controls with an offline toast during a brief reconnect', () => {
    render(<NetworkIndicator />);
    act(() => {
      mocks.connected!(true);
      mocks.connected!(false);
      vi.advanceTimersByTime(1_500);
      mocks.connected!(true);
      vi.advanceTimersByTime(4_000);
    });
    expect(mocks.toast).not.toHaveBeenCalled();
  });

  it('shows a sustained outage once, then dismisses it when connected', () => {
    render(<NetworkIndicator />);
    act(() => {
      mocks.connected!(true);
      mocks.connected!(false);
      vi.advanceTimersByTime(2_000);
      mocks.connected!(false);
      vi.advanceTimersByTime(2_000);
    });
    expect(mocks.toast).toHaveBeenCalledOnce();
    act(() => mocks.connected!(true));
    expect(mocks.toast.dismiss).toHaveBeenLastCalledWith('connection-status');
  });

  it('cancels the pending hint on unmount', () => {
    const { unmount } = render(<NetworkIndicator />);
    act(() => {
      mocks.connected!(true);
      mocks.connected!(false);
    });
    unmount();
    act(() => vi.advanceTimersByTime(4_000));
    expect(mocks.toast).not.toHaveBeenCalled();
    expect(mocks.unsubscribe).toHaveBeenCalledOnce();
  });
});
