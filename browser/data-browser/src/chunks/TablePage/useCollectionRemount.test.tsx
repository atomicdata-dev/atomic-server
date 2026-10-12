// @vitest-environment jsdom
// @wc-ignore-file
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { createElement, type ReactNode } from 'react';
import { afterEach, expect, it, vi } from 'vitest';
import { Collection, Store } from '@tomic/lib';
// The hook under test comes from source, not from the package's built `dist`:
// a `dist` built before this change (a cached build, a stale link) would make
// the test fail for a reason that is not in the code it names.
import { StoreContext } from '../../../../react/src/hooks';
import { useCollection } from '../../../../react/src/useCollection';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

// No socket: a Store that connects drags the test into whatever is (or is not)
// listening on the port, and a failing connection fires store events mid-test.
const newStore = () =>
  new Store({ serverUrl: 'http://localhost:9883', connect: false });

const filter = { property: 'https://x.test/parent', value: 'atomic:parent' };

function fakeRefresh(delayMs: number) {
  vi.spyOn(Collection.prototype, 'refresh').mockImplementation(
    function (this: Collection) {
      const self = this as unknown as { _totalMembers: number };

      return new Promise<void>(resolve =>
        setTimeout(() => {
          self._totalMembers = 4;
          resolve();
        }, delayMs),
      );
    },
  );
}

const wait = (ms: number) =>
  act(async () => {
    await new Promise(r => setTimeout(r, ms));
  });

it('shows the last loaded rows at once when the same query remounts', async () => {
  const store = newStore();
  // Every new collection starts empty and fills after a delay, like a query
  // that has to go through the worker or the network.
  fakeRefresh(20);
  const wrapper = ({ children }: { children: ReactNode }) =>
    createElement(StoreContext.Provider, { value: store }, children);

  const first = renderHook(() => useCollection(filter), { wrapper });
  expect(first.result.current.ready).toBe(false);
  expect(first.result.current.collection.totalMembers).toBe(0);
  await waitFor(() => expect(first.result.current.ready).toBe(true));
  expect(first.result.current.collection.totalMembers).toBe(4);
  first.unmount();

  const second = renderHook(() => useCollection(filter), { wrapper });
  // Synchronously, before anything has been fetched again.
  expect(second.result.current.ready).toBe(true);
  expect(second.result.current.collection.totalMembers).toBe(4);
  await wait(40);
  expect(second.result.current.collection.totalMembers).toBe(4);
});

it('does not borrow rows from a different query', async () => {
  const store = newStore();
  fakeRefresh(0);
  const wrapper = ({ children }: { children: ReactNode }) =>
    createElement(StoreContext.Provider, { value: store }, children);

  const first = renderHook(() => useCollection(filter), { wrapper });
  await wait(10);
  first.unmount();

  const other = renderHook(
    () => useCollection({ ...filter, value: 'atomic:other' }),
    { wrapper },
  );
  expect(other.result.current.ready).toBe(false);
});

it('refreshes the collection that is loading, not the remembered one on screen', async () => {
  const store = newStore();
  const refreshed: Collection[] = [];
  vi.spyOn(Collection.prototype, 'refresh').mockImplementation(
    function (this: Collection) {
      refreshed.push(this);
      const self = this as unknown as { _totalMembers: number };

      return new Promise<void>(resolve =>
        setTimeout(() => {
          self._totalMembers = 4;
          resolve();
        }, 20),
      );
    },
  );
  // Every change looks like a new member whose arrival needs a re-query.
  vi.spyOn(Collection.prototype, 'applyResourceChange').mockReturnValue(
    'membership-stale',
  );
  const wrapper = ({ children }: { children: ReactNode }) =>
    createElement(StoreContext.Provider, { value: store }, children);

  const first = renderHook(() => useCollection(filter), { wrapper });
  await waitFor(() => expect(first.result.current.ready).toBe(true));
  first.unmount();

  // The remount shows the remembered rows while a fresh collection loads.
  const second = renderHook(() => useCollection(filter), { wrapper });
  expect(second.result.current.ready).toBe(true);
  const remembered = refreshed[0];
  const loading = refreshed[refreshed.length - 1];
  expect(loading).not.toBe(remembered);
  const before = refreshed.length;

  // Something is created in the meantime (a duplicated view, say).
  await act(async () => {
    store.notifyResourceUpdated(store.getResourceLoading('x:1'));
    await new Promise(r => setTimeout(r, 5));
  });

  const afterChange = refreshed.slice(before);
  expect(afterChange).toContain(loading);
  expect(afterChange).not.toContain(remembered);
  await wait(40);
  second.unmount();
});
