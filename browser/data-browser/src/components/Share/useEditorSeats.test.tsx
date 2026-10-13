// @vitest-environment jsdom
// @wc-ignore-file
import { afterEach, expect, it, vi } from 'vitest';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import type { Resource } from '@tomic/react';
import { useEditorSeats } from './useEditorSeats';

const mocks = vi.hoisted(() => ({ account: vi.fn(), fetch: vi.fn() }));
vi.mock('@tomic/react', () => ({
  server: { classes: { drive: 'Drive' } },
  useStore: () => ({ getDrive: () => 'atomic:drive' }),
}));
vi.mock('../../helpers/managed/session', () => ({
  getManagedAccount: mocks.account,
}));
vi.mock('../../helpers/managed/api', () => ({ managedFetch: mocks.fetch }));
vi.mock('../../helpers/managed/cloudSync', () => ({
  getManagedPortalUrl: () => 'https://account.example',
}));
const target = { hasClasses: () => false } as unknown as Resource;
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
it('does not ask a protected billing endpoint without an account', async () => {
  mocks.account.mockResolvedValue(null);
  const { result } = renderHook(() => useEditorSeats(target));
  await act(async () => {});
  expect(mocks.account).toHaveBeenCalled();
  expect(mocks.fetch).not.toHaveBeenCalled();
  expect(result.current).toBeUndefined();
});
it('loads the signed-in account seats', async () => {
  mocks.account.mockResolvedValue({ email: 'test@example.com' });
  mocks.fetch.mockResolvedValue(
    Response.json({ plan: 'server', editors_used: 2, editors_included: 5 }),
  );
  const { result } = renderHook(() => useEditorSeats(target));
  await waitFor(() =>
    expect(result.current).toEqual({
      drive: 'atomic:drive',
      used: 2,
      included: 5,
    }),
  );
});
