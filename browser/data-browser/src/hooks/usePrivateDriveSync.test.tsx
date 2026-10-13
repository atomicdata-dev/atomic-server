// @vitest-environment jsdom
// @wc-ignore-file
import { act, cleanup, renderHook } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Store, StoreContext } from '@tomic/react';
import { usePrivateDriveSync } from './usePrivateDriveSync';

afterEach(cleanup);

function setup() {
  const store = new Store({
    serverUrl: 'https://app.example.com',
    connect: false,
  });
  store.setDrive('did:ad:team');
  const live = vi.fn();
  vi.spyOn(store, 'subscribeLive').mockImplementation(live);
  const wrapper = ({ children }: { children: ReactNode }) => (
    <StoreContext value={store}>{children}</StoreContext>
  );

  return { store, live, wrapper };
}

describe('usePrivateDriveSync', () => {
  it('works without an invalidate callback', () => {
    const { store, wrapper } = setup();
    renderHook(() => usePrivateDriveSync('did:ad:private'), { wrapper });

    expect(() => act(() => store.setServerConnected(true))).not.toThrow();
  });

  it('calls the latest callback on connect without resubscribing', () => {
    const { store, live, wrapper } = setup();
    const first = vi.fn();
    const second = vi.fn();
    const { rerender } = renderHook(
      ({ cb }) => usePrivateDriveSync('did:ad:private', cb),
      { wrapper, initialProps: { cb: first } },
    );
    rerender({ cb: second });
    act(() => store.setServerConnected(true));

    expect(first).not.toHaveBeenCalled();
    expect(second).toHaveBeenCalledTimes(1);
    expect(live).toHaveBeenCalledTimes(1);
  });

  it('does not subscribe when the private drive is the active drive', () => {
    const { live, wrapper } = setup();
    renderHook(() => usePrivateDriveSync('did:ad:team'), { wrapper });

    expect(live).not.toHaveBeenCalled();
  });
});
