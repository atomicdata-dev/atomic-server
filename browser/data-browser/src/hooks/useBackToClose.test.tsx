// @vitest-environment jsdom
import React, { useState } from 'react';
import { act, renderHook } from '@testing-library/react';
import { createMemoryHistory } from '@tanstack/react-router';
import { beforeEach, expect, it, vi } from 'vitest';
import { useBackToClose } from './useBackToClose';

const fixture = vi.hoisted(() => ({ history: undefined as unknown }));
vi.mock('@tanstack/react-router', async importOriginal => ({
  ...(await importOriginal<typeof import('@tanstack/react-router')>()),
  useRouter: () => fixture,
}));
let history: ReturnType<typeof createMemoryHistory>;
beforeEach(() => {
  history = createMemoryHistory({ initialEntries: ['/previous', '/page'] });
  fixture.history = history;
});

it('Back closes the menu and stays on the page, including under StrictMode', () => {
  const { result } = renderHook(
    () => {
      const [open, setOpen] = useState(true);
      useBackToClose(open, () => setOpen(false));

      return open;
    },
    { wrapper: React.StrictMode },
  );
  expect(history.length).toBe(3);
  act(() => history.back());
  expect(result.current).toBe(false);
  expect(history.location.href).toBe('/page');
});

it('closing by other means removes only its own entry', () => {
  const { rerender } = renderHook(
    ({ open }) => {
      useBackToClose(open, vi.fn());
    },
    { initialProps: { open: true } },
  );
  rerender({ open: false });
  expect(history.location.href).toBe('/page');
  act(() => history.back());
  expect(history.location.href).toBe('/previous');
});

it('an item that navigates keeps its destination and does not pop', () => {
  const close = vi.fn();
  const { rerender } = renderHook(({ open }) => useBackToClose(open, close), {
    initialProps: { open: true },
  });
  act(() => history.push('/next'));
  expect(close).toHaveBeenCalledOnce();
  rerender({ open: false });
  expect(history.location.href).toBe('/next');
});
