// @vitest-environment jsdom
// @wc-ignore-file
import React from 'react';
import { expect, it, vi } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { Store, StoreContext, type Agent } from '@tomic/react';
import { usePrivateDrive } from './usePrivateDrive';

let agent: Agent | undefined;
const resolve = vi.hoisted(() => vi.fn());
vi.mock('../helpers/AppSettings', () => ({ useSettings: () => ({ agent }) }));
vi.mock('../helpers/privateDrive', () => ({
  fetchPrivateDriveSubject: resolve,
}));

it('never returns the previous account’s home during a new account render', async () => {
  const store = new Store({ serverUrl: 'https://example.com', connect: false });
  agent = { initialDrive: 'atomic:first' } as Agent;
  resolve.mockResolvedValueOnce('atomic:first-resolved');
  const observed: (string | undefined)[] = [];
  const wrapper = ({ children }: { children: React.ReactNode }) =>
    React.createElement(StoreContext.Provider, { value: store }, children);
  const { result, rerender, unmount } = renderHook(
    () => {
      const home = usePrivateDrive();
      observed.push(home.privateDrive);

      return home;
    },
    { wrapper },
  );
  await waitFor(() =>
    expect(result.current.privateDrive).toBe('atomic:first-resolved'),
  );
  agent = { initialDrive: 'atomic:second' } as Agent;
  resolve.mockReturnValueOnce(new Promise(() => {}));
  observed.length = 0;
  rerender();
  expect(observed).not.toContain('atomic:first-resolved');
  expect(result.current.privateDrive).toBe('atomic:second');
  agent = undefined;
  observed.length = 0;
  rerender();
  expect(observed.every(home => home === undefined)).toBe(true);
  expect(result.current.loading).toBe(false);
  unmount();
});
